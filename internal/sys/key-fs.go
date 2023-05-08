// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/kv"
)

// NewKeyFS returns a new KeyFS that
// reads/writes keys from/to the given
// directory path and en/decrypts them
// with the given encryption key.
func NewKeyFS(filename string, key key.Key) KeyFS {
	return &keyFS{
		rootDir: filename,
		rootKey: key,
	}
}

type keyFS struct {
	rootDir string
	rootKey key.Key
}

func (fs *keyFS) CreateKey(_ context.Context, name string, key key.Key) error {
	if err := valid(name); err != nil {
		return err
	}

	// First, we write the key to a temporary file.
	// The tmp file name contains a character ('.')
	// that is not allowed for client-specified key names.
	// Therefore, clients cannot create a key with the
	// same name.
	// Then we rename this temporary file to the actual
	// key file in one "atomic" operation.
	const TmpFile = ".key.tmp"
	filename := filepath.Join(fs.rootDir, TmpFile)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	plaintext, err := key.MarshalBinary()
	if err != nil {
		return err
	}
	ciphertext, err := fs.rootKey.Wrap(plaintext, []byte(name))
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

	if err = os.Rename(filename, filepath.Join(fs.rootDir, name)); err != nil {
		os.Remove(filename)
		return err
	}
	return nil
}

func (fs *keyFS) GetKey(_ context.Context, name string) (key.Key, error) {
	if err := valid(name); err != nil {
		return key.Key{}, err
	}
	filename := filepath.Join(fs.rootDir, name)
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return key.Key{}, kes.ErrKeyNotFound
	}
	if err != nil {
		return key.Key{}, err
	}
	defer file.Close()

	var ciphertext bytes.Buffer
	if _, err := io.Copy(&ciphertext, mem.LimitReader(file, key.MaxSize)); err != nil {
		return key.Key{}, err
	}
	plaintext, err := fs.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		return key.Key{}, err
	}

	var k key.Key
	if err = k.UnmarshalBinary(plaintext); err != nil {
		return key.Key{}, err
	}
	return k, nil
}

func (fs *keyFS) DeleteKey(_ context.Context, name string) error {
	if err := valid(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(fs.rootDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return kes.ErrKeyNotFound
	}
	return err
}

func (fs *keyFS) ListKeys(ctx context.Context) (kv.Iter[string], error) {
	file, err := os.Open(fs.rootDir)
	if err != nil {
		return nil, err
	}
	return &keyIterator{
		ctx: ctx,
		dir: file,
	}, nil
}

type keyIterator struct {
	ctx   context.Context
	dir   *os.File
	names []string
	next  string
	err   error
}

func (i *keyIterator) Next() (string, bool) {
	const TmpFile = ".key.tmp"
	if len(i.names) > 0 {
		if i.names[0] == TmpFile {
			i.names = i.names[1:]
		}
	}
	if len(i.names) > 0 {
		v := i.names[0]
		i.names = i.names[1:]
		return v, true
	}
	if i.err != nil {
		return "", false
	}

	select {
	case <-i.ctx.Done():
		i.err = i.ctx.Err()
		return "", false
	default:
	}

	const N = 250
	i.names, i.err = i.dir.Readdirnames(N)
	if i.err != nil && i.err != io.EOF {
		return "", false
	}
	if len(i.names) == 0 && i.err == io.EOF {
		return "", false
	}
	if i.names[0] == TmpFile {
		i.names = i.names[1:]
	}
	if len(i.names) > 0 {
		v := i.names[0]
		i.names = i.names[1:]
		return v, true
	}
	return "", false
}

func (i *keyIterator) Name() string { return i.next }

func (i *keyIterator) Close() error {
	if err := i.dir.Close(); i.err == nil || i.err == io.EOF {
		return err
	}
	return i.err
}
