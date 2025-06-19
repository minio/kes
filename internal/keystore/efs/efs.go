// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package efs implements a key-value store that
// stores keys as file names and values as encrypted
// file content.
//
// It wraps a fs store and in addition, encrypt the keys.
package efs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/keystore/fs"
)

// NewStore returns a new Store that reads
// from and writes to the given directory,
// using encryption.
//
// If the directory or any parent directory
// does not exist, NewStore creates them all.
//
// It returns an error if dir exists but is
// not a directory.
func NewStore(keyPath string, keyCipher string, dir string) (*Store, error) {
	fsStore, err := fs.NewStore(dir)
	if err != nil {
		return nil, err
	}

	key, err := loadMasterKey(keyPath, keyCipher)
	if err != nil {
		return nil, err
	}

	return &Store{key: key, fsStore: fsStore}, nil
}

// loadMasterKey reads a secret key from a
// given path.
//
// If the key file does not exist, or contains
// an unexpected amount of bytes, it returns an error.
func loadMasterKey(keyPath string, keyCipher string) (crypto.SecretKey, error) {
	file, err := os.Open(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return crypto.SecretKey{}, fmt.Errorf("master key not found: '%s'", keyPath)
	}
	if err != nil {
		return crypto.SecretKey{}, err
	}
	defer file.Close()

	const MaxSize = crypto.SecretKeySize + 1
	value, err := io.ReadAll(mem.LimitReader(file, MaxSize))
	if err != nil {
		return crypto.SecretKey{}, err
	}
	if err = file.Close(); err != nil {
		return crypto.SecretKey{}, err
	}
	if len(value) != crypto.SecretKeySize {
		return crypto.SecretKey{}, fmt.Errorf("invalid master key size for '%s'", keyCipher)
	}

	cipher, err := crypto.ParseSecretKeyType(keyCipher)
	if err != nil {
		return crypto.SecretKey{}, err
	}
	if cipher == crypto.ChaCha20 && fips.Enabled {
		return crypto.SecretKey{}, fmt.Errorf("master key algorithm '%s' not supported by FIPS 140-2", keyCipher)
	}

	return crypto.NewSecretKey(cipher, value)
}

// Store is a connection to a directory on
// the filesystem using a secret key to encrypt the files.
//
// It implements the kms.Store interface and
// acts as KMS abstraction over a filesystem.
type Store struct {
	key     crypto.SecretKey
	fsStore *fs.Store
}

func (s *Store) String() string { return "Encrypted Filesystem: " + s.fsStore.Dir() }

// Status returns the current state of the Conn.
//
// In particular, it reports whether the underlying
// filesystem is accessible.
func (s *Store) Status(ctx context.Context) (kes.KeyStoreState, error) {
	return s.fsStore.Status(ctx)
}

// Create creates a new file with the given name inside
// the Conn directory if and only if no such file exists.
//
// It returns kes.ErrKeyExists if such a file already exists.
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	context := fmt.Sprintf("name=%s", name)
	encryptedValue, err := s.key.Encrypt(value, []byte(context))
	if err != nil {
		return err
	}

	return s.fsStore.Create(ctx, name, encryptedValue)
}

// Get reads the content of the named file within the Conn
// directory. It returns kes.ErrKeyNotFound if no such file
// exists.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	encryptedValue, err := s.fsStore.Get(ctx, name)
	if err != nil {
		return nil, err
	}

	context := fmt.Sprintf("name=%s", name)
	value, err := s.key.Decrypt(encryptedValue, []byte(context))
	if err != nil {
		return nil, err
	}

	return value, nil
}

// Delete deletes the named file within the Conn directory if
// and only if it exists. It returns kes.ErrKeyNotFound if
// no such file exists.
func (s *Store) Delete(ctx context.Context, name string) error {
	return s.fsStore.Delete(ctx, name)
}

// List returns a new Iterator over the names of
// all stored keys.
// List returns the first n key names, that start with the given
// prefix, and the next prefix from which the listing should
// continue.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty
func (s *Store) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	return s.fsStore.List(ctx, prefix, n)
}

// Close closes the Store.
func (s *Store) Close() error {
	return s.fsStore.Close()
}
