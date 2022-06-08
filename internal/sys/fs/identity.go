// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
)

const identityAdminDir = ".admin"

// CreateIdentitySet creates a new auth.IdentitySet at the given path
// with the given admin identity.
func CreateIdentitySet(filename string, rootKey key.Key, admin kes.Identity) error {
	if err := os.MkdirAll(filepath.Join(filename, identityAdminDir), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	associatedData := []byte(path.Join(identityAdminDir, admin.String()))
	return writeIdentityInfo(filepath.Join(filename, identityAdminDir, admin.String()), rootKey, auth.IdentityInfo{
		Policy:    "",
		IsAdmin:   true,
		CreatedAt: time.Now().UTC(),
		CreatedBy: rootKey.CreatedBy(),
	}, associatedData)
}

// OpenIdentitySet opens a new auth.IdentitySet at the given path.
func OpenIdentitySet(filename string, rootKey key.Key, errorLog *log.Logger) (auth.IdentitySet, error) {
	f, err := os.Open(filepath.Join(filename, identityAdminDir))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	files, err := f.Readdirnames(1)
	if err != nil {
		return nil, err
	}

	admin := kes.Identity(files[0])
	associatedData := []byte(path.Join(identityAdminDir, admin.String()))
	info, err := readIdentityInfo(filepath.Join(filename, identityAdminDir, admin.String()), rootKey, associatedData)
	if err != nil {
		return nil, err
	}
	return &identitySet{
		path:       filename,
		rootKey:    rootKey,
		errorLog:   errorLog,
		admin:      admin,
		adminInfo:  info,
		identities: map[kes.Identity]auth.IdentityInfo{},
	}, nil
}

type identitySet struct {
	path     string
	rootKey  key.Key
	errorLog *log.Logger

	lock       sync.RWMutex
	admin      kes.Identity
	adminInfo  auth.IdentityInfo
	identities map[kes.Identity]auth.IdentityInfo
}

func (i *identitySet) Admin(ctx context.Context) (kes.Identity, error) {
	i.lock.RLock()
	defer i.lock.RUnlock()

	return i.admin, nil
}

func (i *identitySet) SetAdmin(ctx context.Context, admin kes.Identity) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	_, err := os.Stat(filepath.Join(i.path, admin.String()))
	if err == nil {
		return kes.NewError(http.StatusConflict, "identity already exists")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		xlog.Printf(i.errorLog, "fs: failed to set admin identity '%s': failed to stat '%s': %v", admin, filepath.Join(i.path, admin.String()), err)
		return err
	}

	info := auth.IdentityInfo{
		Policy:    "",
		IsAdmin:   true,
		CreatedAt: time.Now().UTC(),
		CreatedBy: i.rootKey.CreatedBy(), // TODO
	}
	associactedData := []byte(path.Join(identityAdminDir, admin.String()))
	if err := writeIdentityInfo(filepath.Join(i.path, identityAdminDir, admin.String()), i.rootKey, info, associactedData); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to set admin identity '%s': %v", admin, err)
		return err
	}
	return nil
}

func (i *identitySet) Assign(ctx context.Context, policy string, identity kes.Identity) error {
	if err := validatePath(policy); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to assign policy '%s' to identity '%v': invalid policy name: %v", policy, identity, err)
		return err
	}
	if err := validatePath(identity.String()); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to assign policy '%s' to identity '%v': invalid identity: %v", policy, identity, err)
		return err
	}

	i.lock.Lock()
	defer i.lock.Unlock()

	if identity == i.admin {
		return kes.NewError(http.StatusConflict, "identity is admin")
	}
	info := auth.IdentityInfo{
		Policy:    policy,
		IsAdmin:   false,
		CreatedAt: time.Now().UTC(),
		CreatedBy: "", // TODO
	}
	if err := writeIdentityInfo(filepath.Join(i.path, identity.String()), i.rootKey, info, []byte(identity.String())); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to assign policy '%s' to '%v': %v", policy, identity, err)
		return err
	}
	return nil
}

func (i *identitySet) Get(ctx context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if err := validatePath(identity.String()); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to get identity '%v': invalid identity: %v", identity, err)
		return auth.IdentityInfo{}, err
	}

	i.lock.RLock()
	if identity == i.admin {
		return i.adminInfo, nil
	}
	if info, ok := i.identities[identity]; ok {
		i.lock.RUnlock()
		return info, nil
	}
	i.lock.RUnlock()

	i.lock.Lock()
	defer i.lock.Unlock()

	info, err := readIdentityInfo(filepath.Join(i.path, identity.String()), i.rootKey, []byte(identity.String()))
	if errors.Is(err, os.ErrNotExist) {
		return info, auth.ErrIdentityNotFound
	}
	if err != nil {
		xlog.Printf(i.errorLog, "fs: failed to get identity '%v': %v", identity, err)
		return info, err
	}
	i.identities[identity] = info
	return info, nil
}

func (i *identitySet) Delete(ctx context.Context, identity kes.Identity) error {
	if err := validatePath(identity.String()); err != nil {
		xlog.Printf(i.errorLog, "fs: failed to delete identity '%v': invalid identity: %v", identity, err)
		return err
	}

	i.lock.Lock()
	defer i.lock.Unlock()

	if identity == i.admin {
		return kes.NewError(http.StatusConflict, "cannot delete admin")
	}

	delete(i.identities, identity)
	path := filepath.Join(i.path, identity.String())
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return auth.ErrIdentityNotFound
		}
		xlog.Printf(i.errorLog, "fs: failed to delete identity '%v': %v", identity, err)
		return err
	}
	return nil
}

func (i *identitySet) List(ctx context.Context) (auth.IdentityIterator, error) {
	dir, err := os.Open(i.path)
	if err != nil {
		xlog.Printf(i.errorLog, "fs: failed to list identities '%v'", err)
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
	if len(i.names) > 0 {
		if i.names[0] == identityAdminDir {
			i.names = i.names[1:]
			if len(i.names) == 0 {
				return false
			}
		}
		i.next, i.names = kes.Identity(i.names[0]), i.names[1:]
		return true
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
	if i.names[0] == identityAdminDir {
		i.names = i.names[1:]
		if len(i.names) == 0 {
			return false
		}
	}
	i.next, i.names = kes.Identity(i.names[0]), i.names[1:]
	return true
}

func (i *identityIterator) Identity() kes.Identity { return i.next }

func (i *identityIterator) Close() error {
	if err := i.dir.Close(); i.err == nil || i.err == io.EOF {
		return err
	}
	return i.err
}

func readIdentityInfo(path string, key key.Key, associatedData []byte) (auth.IdentityInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return auth.IdentityInfo{}, err
	}
	defer file.Close()

	var ciphertext bytes.Buffer
	if _, err := io.Copy(&ciphertext, io.LimitReader(file, 1<<20)); err != nil {
		return auth.IdentityInfo{}, err
	}
	plaintext, err := key.Unwrap(ciphertext.Bytes(), associatedData)
	if err != nil {
		return auth.IdentityInfo{}, err
	}

	var info auth.IdentityInfo
	if err = info.UnmarshalBinary(plaintext); err != nil {
		return auth.IdentityInfo{}, err
	}
	return info, nil
}

func writeIdentityInfo(path string, key key.Key, info auth.IdentityInfo, associatedData []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	plaintext, err := info.MarshalBinary()
	if err != nil {
		return err
	}
	ciphertext, err := key.Wrap(plaintext, associatedData)
	if err != nil {
		return err
	}
	if _, err = file.Write(ciphertext); err != nil {
		os.Remove(path)
		return err
	}
	return file.Sync()
}
