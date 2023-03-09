// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
)

// NewIdentityFS returns a new IdentityFS that
// reads/writes identities from/to the given
// directory path and en/decrypts them
// with the given encryption key.
func NewIdentityFS(filename string, key key.Key) IdentityFS {
	return &identityFS{
		rootDir: filename,
		rootKey: key,
	}
}

var _ IdentityFS = (*identityFS)(nil)

type identityFS struct {
	rootDir string
	rootKey key.Key
}

func (fs *identityFS) Admin(_ context.Context) (kes.Identity, error) {
	const (
		AdminDir = ".admin"
		TmpFile  = ".admin.tmp"
	)
	dir, err := os.Open(filepath.Join(fs.rootDir, AdminDir))
	if err != nil {
		return "", err
	}
	defer dir.Close()

	files, err := dir.Readdirnames(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if len(files) > 1 && files[0] == TmpFile {
		files[0] = files[1]
	}
	admin := files[0]
	file, err := os.Open(filepath.Join(fs.rootDir, AdminDir, admin))
	if err != nil {
		return "", err
	}
	defer file.Close()

	const MaxSize = 1 * mem.MiB
	var ciphertext bytes.Buffer
	if _, err = io.Copy(&ciphertext, mem.LimitReader(file, MaxSize)); err != nil {
		return "", err
	}
	plaintext, err := fs.rootKey.Unwrap(ciphertext.Bytes(), []byte(path.Join(AdminDir, admin)))
	if err != nil {
		return "", err
	}

	var info auth.IdentityInfo
	if err = info.UnmarshalBinary(plaintext); err != nil {
		return "", err
	}
	if !info.IsAdmin {
		return "", errors.New("sys: identity is not an admin")
	}
	return kes.Identity(admin), nil
}

func (fs *identityFS) SetAdmin(_ context.Context, admin kes.Identity) error {
	if err := valid(admin.String()); err != nil {
		return err
	}

	// Check that the new admin identity does not exist as user
	// identity. An identity must not be a regular user and admin
	// at the same time.
	_, err := os.Stat(filepath.Join(fs.rootDir, admin.String()))
	if err == nil {
		return kes.NewError(http.StatusConflict, "identity already exists")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// First, write the admin identity to a temporary file
	// with a filename that cannot be a client-specified
	// admin identity - i.e. contains invalid character ('.').
	//
	// Then rename that temporary file to the actual admin
	// identity file in one "atomic" operation. This avoids
	// partial/broken files in case of a write error.
	const (
		AdminDir = ".admin"
		TmpFile  = ".admin.tmp"
	)
	filename := filepath.Join(fs.rootDir, AdminDir, TmpFile)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		// Creating the '.admin.tmp' file can only return ErrNotExist
		// if only if one of the parent directories does not exist.
		//
		// This is the case when creating the enclave - i.e. the
		// '.admin' directory does not exist.
		// Hence, we create the '.admin' directory and try again.
		if err = os.Mkdir(filepath.Join(fs.rootDir, AdminDir), 0o755); err != nil {
			return err
		}
		file, err = os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	}
	if err != nil {
		return err
	}
	defer file.Close()

	info := auth.IdentityInfo{
		Policy:    "",
		IsAdmin:   true,
		CreatedAt: time.Now().UTC(),
		CreatedBy: fs.rootKey.CreatedBy(), // TODO
	}
	plaintext, err := info.MarshalBinary()
	if err != nil {
		return err
	}
	ciphertext, err := fs.rootKey.Wrap(plaintext, []byte(path.Join(AdminDir, admin.String())))
	if err != nil {
		return err
	}

	n, err := file.Write(ciphertext)
	if err != nil {
		return err
	}
	if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}

	if err = os.Rename(filename, filepath.Join(fs.rootDir, AdminDir, admin.String())); err != nil {
		os.Remove(filename)
		return err
	}
	return nil
}

func (fs *identityFS) AssignPolicy(_ context.Context, policy string, identity kes.Identity) error {
	if err := valid(identity.String()); err != nil {
		return err
	}

	// First, write the identity to a temporary file
	// with a filename that cannot be a client-specified
	// identity - i.e. contains invalid character ('.').
	//
	// Then rename that temporary file to the actual identity
	// file in one "atomic" operation. This avoids partial/broken
	// files in case of a write error.
	const TmpFile = ".identity.tmp"
	filename := filepath.Join(fs.rootDir, TmpFile)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	info := auth.IdentityInfo{
		Policy:    policy,
		IsAdmin:   false,
		CreatedAt: time.Now().UTC(),
		CreatedBy: "", // TODO
	}
	plaintext, err := info.MarshalBinary()
	if err != nil {
		return err
	}
	ciphertext, err := fs.rootKey.Wrap(plaintext, []byte(identity.String()))
	if err != nil {
		return err
	}

	n, err := file.Write(ciphertext)
	if err != nil {
		return err
	}
	if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}

	if err = os.Rename(filename, filepath.Join(fs.rootDir, identity.String())); err != nil {
		os.Remove(filename)
		return err
	}
	return nil
}

func (fs *identityFS) DeleteIdentity(_ context.Context, identity kes.Identity) error {
	if err := valid(identity.String()); err != nil {
		return err
	}

	err := os.Remove(filepath.Join(fs.rootDir, identity.String()))
	if errors.Is(err, os.ErrNotExist) {
		return kes.ErrIdentityNotFound
	}
	return err
}

func (fs *identityFS) GetIdentity(_ context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if err := valid(identity.String()); err != nil {
		return auth.IdentityInfo{}, err
	}

	const AdminDir = ".admin"
	associatedData := []byte(identity)

	filename := filepath.Join(fs.rootDir, identity.String())
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		associatedData = []byte(path.Join(AdminDir, identity.String()))
		filename = filepath.Join(fs.rootDir, AdminDir, identity.String())
		file, err = os.Open(filename)
		if errors.Is(err, os.ErrNotExist) {
			return auth.IdentityInfo{}, kes.ErrIdentityNotFound
		}
	}
	if err != nil {
		return auth.IdentityInfo{}, err
	}
	defer file.Close()

	const MaxSize = 1 * mem.MiB
	var ciphertext bytes.Buffer
	if _, err = io.Copy(&ciphertext, mem.LimitReader(file, MaxSize)); err != nil {
		return auth.IdentityInfo{}, err
	}
	plaintext, err := fs.rootKey.Unwrap(ciphertext.Bytes(), associatedData)
	if err != nil {
		return auth.IdentityInfo{}, err
	}

	var info auth.IdentityInfo
	if err = info.UnmarshalBinary(plaintext); err != nil {
		return auth.IdentityInfo{}, err
	}
	return info, nil
}

func (fs *identityFS) ListIdentities(ctx context.Context) (auth.IdentityIterator, error) {
	dir, err := os.Open(fs.rootDir)
	if err != nil {
		return nil, err
	}
	return &identityIterator{
		ctx: ctx,
		dir: dir,
	}, nil
}

type identityIterator struct {
	ctx   context.Context
	dir   *os.File
	names []string
	next  kes.Identity
	err   error
}

func (i *identityIterator) Next() bool {
	const (
		AdminDir = ".admin"
		TmpFile  = ".identity.tmp"
	)
	if len(i.names) > 0 {
		if name := i.names[0]; name != AdminDir && name != TmpFile {
			i.next, i.names = kes.Identity(name), i.names[1:]
			return true
		}
		for len(i.names) > 0 {
			if name := i.names[0]; name == AdminDir || name == TmpFile {
				i.names = i.names[1:]
				continue
			}
			i.next, i.names = kes.Identity(i.names[0]), i.names[1:]
			return true
		}
		return false
	}
	if i.err != nil {
		return false
	}

	select {
	case <-i.ctx.Done():
		i.err = i.ctx.Err()
		return false
	default:
	}

	const N = 250
	i.names, i.err = i.dir.Readdirnames(N)
	if i.err != nil && i.err != io.EOF {
		return false
	}
	if len(i.names) == 0 && i.err == io.EOF {
		return false
	}
	for len(i.names) > 0 {
		if name := i.names[0]; name == AdminDir || name == TmpFile {
			i.names = i.names[1:]
			continue
		}
		i.next, i.names = kes.Identity(i.names[0]), i.names[1:]
		return true
	}
	return false
}

func (i *identityIterator) Identity() kes.Identity { return i.next }

func (i *identityIterator) Close() error {
	if err := i.dir.Close(); i.err == nil || i.err == io.EOF {
		return err
	}
	return i.err
}
