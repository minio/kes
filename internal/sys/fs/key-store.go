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
	"os"
	"path/filepath"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
)

// CreateKeyStore creates a new key.Store at the given path.
func CreateKeyStore(path string) error { return os.MkdirAll(path, 0o755) }

// OpenKeyStore opens the key.Store at the given path.
func OpenKeyStore(path string, key key.Key, errorLog *log.Logger) (key.Store, error) {
	return &keyStore{
		path:     path,
		rootKey:  key,
		errorLog: errorLog,
	}, nil
}

type keyStore struct {
	path    string
	rootKey key.Key

	errorLog *log.Logger
}

var _ key.Store = (*keyStore)(nil) // compiler check

func (s *keyStore) Status(context.Context) (key.StoreState, error) { return key.StoreState{}, nil }

func (s *keyStore) Create(ctx context.Context, name string, key key.Key) error {
	if err := validatePath(name); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': invalid key name: %v", name, err)
		return err
	}

	// We use os.O_CREATE and os.O_EXCL to enforce that the
	// file must not have existed before.
	path := filepath.Join(s.path, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return kes.ErrKeyExists
	}
	if err != nil {
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to open '%s': %v", name, path, err)
		return err
	}
	defer file.Close()

	plaintext, err := key.MarshalBinary()
	if err != nil {
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to encode key: %v", name, err)
		return err
	}
	ciphertext, err := s.rootKey.Wrap(plaintext, []byte(name))
	if err != nil {
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to encrypt key: %v", name, err)
		return err
	}

	if _, err = file.Write(ciphertext); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to write to '%s': %v", name, path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to remove '%s': %v", name, path, rmErr)
		}
		return err
	}
	if err = file.Sync(); err != nil { // Ensure that we wrote the value to disk
		xlog.Printf(s.errorLog, "fs: failed to create key '%s': fs sync failed: %v", name, err)
		if rmErr := os.Remove(path); rmErr != nil {
			xlog.Printf(s.errorLog, "fs: failed to create key '%s': failed to remove '%s': %v", name, path, rmErr)
		}
		return err
	}
	return nil
}

func (s *keyStore) Delete(ctx context.Context, name string) error {
	if err := validatePath(name); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to delete key '%s': invalid key name: %v", name, err)
		return err
	}
	path := filepath.Join(s.path, name)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return kes.ErrKeyNotFound
		}
		xlog.Printf(s.errorLog, "fs: failed to delete key '%s': %v", name, err)
		return err
	}
	return nil
}

func (s *keyStore) Get(ctx context.Context, name string) (key.Key, error) {
	if err := validatePath(name); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to get key '%s': invalid key name: %v", name, err)
		return key.Key{}, err
	}

	path := filepath.Join(s.path, name)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return key.Key{}, kes.ErrKeyNotFound
		}
		xlog.Printf(s.errorLog, "fs: failed to get key '%s': failed to open '%s': %v", name, path, err)
		return key.Key{}, err
	}
	defer file.Close()

	var ciphertext bytes.Buffer
	if _, err := io.Copy(&ciphertext, io.LimitReader(file, key.MaxSize)); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to get key '%s': failed to read from '%s': %v", name, path, err)
		return key.Key{}, err
	}
	plaintext, err := s.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		xlog.Printf(s.errorLog, "fs: failed to get key '%s': failed to decrypt key: %v", name, err)
		return key.Key{}, err
	}

	var k key.Key
	if err = k.UnmarshalBinary(plaintext); err != nil {
		xlog.Printf(s.errorLog, "fs: failed to get key '%s': failed to parse key: %v", name, err)
		return key.Key{}, err
	}
	return k, nil
}

func (s *keyStore) List(ctx context.Context) (key.Iterator, error) {
	dir, err := os.Open(s.path)
	if err != nil {
		xlog.Printf(s.errorLog, "fs: failed to list keys '%v'", err)
		return nil, err
	}
	return &keyIterator{
		ctx: ctx,
		dir: dir,
	}, nil
}

type keyIterator struct {
	ctx   context.Context
	dir   *os.File
	names []string
	next  string
	err   error
}

func (i *keyIterator) Next() bool {
	if len(i.names) > 0 {
		i.next, i.names = i.names[0], i.names[1:]
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
	i.next, i.names = i.names[0], i.names[1:]
	return true
}

func (i *keyIterator) Name() string { return i.next }

func (i *keyIterator) Err() error {
	if err := i.dir.Close(); i.err == nil || i.err == io.EOF {
		return err
	}
	return i.err
}
