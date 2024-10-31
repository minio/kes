// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package fs implements a key-value store that
// stores keys as file names and values as file
// content.
package fs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/keystore"
	kesdk "github.com/minio/kms-go/kes"
)

// NewStore returns a new Store that reads
// from and writes to the given directory.
//
// If the directory or any parent directory
// does not exist, NewStore creates them all.
//
// It returns an error if dir exists but is
// not a directory.
func NewStore(dir string) (*Store, error) {
	switch file, err := os.Stat(dir); {
	case errors.Is(err, os.ErrNotExist):
		if err = os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		if !file.Mode().IsDir() {
			return nil, errors.New("fs: '" + dir + "' is not a directory")
		}
	}
	return &Store{dir: dir}, nil
}

// Store is a connection to a directory on
// the filesystem.
//
// It implements the kms.Store interface and
// acts as KMS abstraction over a filesystem.
type Store struct {
	dir  string
	lock sync.RWMutex
}

func (s *Store) String() string { return "Filesystem: " + s.dir }

// Dir returns the directory used on the filesystem.
func (s *Store) Dir() string { return s.dir }

// Status returns the current state of the Conn.
//
// In particular, it reports whether the underlying
// filesystem is accessible.
func (s *Store) Status(context.Context) (kes.KeyStoreState, error) {
	start := time.Now()
	if _, err := os.Stat(s.dir); err != nil {
		return kes.KeyStoreState{}, &keystore.ErrUnreachable{Err: err}
	}
	return kes.KeyStoreState{
		Latency: time.Since(start),
	}, nil
}

// Create creates a new file with the given name inside
// the Conn directory if and only if no such file exists.
//
// It returns kes.ErrKeyExists if such a file already exists.
func (s *Store) Create(_ context.Context, name string, value []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	filename := filepath.Join(s.dir, name)
	switch err := s.create(filename, value); {
	case errors.Is(err, os.ErrExist):
		return kesdk.ErrKeyExists
	case err != nil:
		os.Remove(filename)
		return err
	}
	return nil
}

// Get reads the content of the named file within the Conn
// directory. It returns kes.ErrKeyNotFound if no such file
// exists.
func (s *Store) Get(_ context.Context, name string) ([]byte, error) {
	const MaxSize = 1 * mem.MiB

	if err := validName(name); err != nil {
		return nil, err
	}
	s.lock.RLock()
	defer s.lock.RUnlock()

	file, err := os.Open(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, kesdk.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	value, err := io.ReadAll(mem.LimitReader(file, MaxSize))
	if err != nil {
		return nil, err
	}
	if err = file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}

// Delete deletes the named file within the Conn directory if
// and only if it exists. It returns kes.ErrKeyNotFound if
// no such file exists.
func (s *Store) Delete(_ context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	switch err := os.Remove(filepath.Join(s.dir, name)); {
	case errors.Is(err, os.ErrNotExist):
		return kesdk.ErrKeyNotFound
	default:
		return err
	}
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
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, "", err
	}
	select {
	case <-ctx.Done():
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		return nil, "", context.Canceled
	default:
		return keystore.List(names, prefix, n)
	}
}

// Close closes the Store.
func (s *Store) Close() error { return nil }

func (s *Store) create(filename string, value []byte) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	n, err := file.Write(value)
	if err != nil {
		return err
	}
	if n != len(value) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func validName(name string) error {
	if name == "" || strings.IndexFunc(name, func(c rune) bool {
		return c == '/' || c == '\\' || c == '.'
	}) >= 0 {
		return errors.New("fs: key name contains invalid character")
	}
	return nil
}
