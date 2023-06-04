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
	"sort"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/edge/kv"
)

// New returns a new Store that reads
// from and writes to the given directory.
//
// If the directory or any parent directory
// does not exist, New creates them all.
//
// It returns an error if dir exists but is
// not a directory.
func New(dir string) (*FS, error) {
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
	return &FS{dir: dir}, nil
}

// FS is a connection to a directory on
// the filesystem.
//
// It implements the kms.FS interface and
// acts as KMS abstraction over a fileystem.
type FS struct {
	dir  string
	lock sync.RWMutex
}

func (s *FS) Path() string { return s.dir }

// Status returns the current state of the Conn.
//
// In particular, it reports whether the underlying
// filesystem is accessible.
func (s *FS) Status(context.Context) (edge.KeyStoreState, error) {
	start := time.Now()
	if _, err := os.Stat(s.dir); err != nil {
		return edge.KeyStoreState{}, &kv.Unreachable{Err: err}
	}
	return edge.KeyStoreState{
		Latency: time.Since(start),
	}, nil
}

// Create creates a new file with the given name inside
// the Conn directory if and only if no such file exists.
//
// It returns kes.ErrKeyExists if such a file already exists.
func (s *FS) Create(_ context.Context, name string, value []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	s.lock.Lock()
	defer s.lock.Unlock()

	filename := filepath.Join(s.dir, name)
	switch err := s.create(filename, value); {
	case errors.Is(err, os.ErrExist):
		return kes.ErrKeyExists
	case err != nil:
		os.Remove(filename)
		return err
	}
	return nil
}

// Set creates a new file with the given name inside
// the Conn directory if and only if no such file exists.
//
// It returns kes.ErrKeyExists if such a file already exists.
func (s *FS) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
}

// Get reads the content of the named file within the Conn
// directory. It returns kes.ErrKeyNotFound if no such file
// exists.
func (s *FS) Get(_ context.Context, name string) ([]byte, error) {
	const MaxSize = 1 * mem.MiB

	if err := validName(name); err != nil {
		return nil, err
	}
	s.lock.RLock()
	defer s.lock.RUnlock()

	file, err := os.Open(filepath.Join(s.dir, name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, kes.ErrKeyNotFound
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
func (s *FS) Delete(_ context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	switch err := os.Remove(filepath.Join(s.dir, name)); {
	case errors.Is(err, os.ErrNotExist):
		return kes.ErrKeyNotFound
	default:
		return err
	}
}

// List returns a Iter over the files within the Conn directory.
// The Iter must be closed to release any filesystem resources
// back to the OS.
func (s *FS) List(_ context.Context, prefix string, n int) ([]string, string, error) {
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, "", err
	}
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, "", err
	}
	sort.Strings(names)

	if prefix == "" {
		if n > 0 && n < len(names) {
			return names[:n], names[n], nil
		}
		return names, "", nil
	}

	j := -1
	for i, name := range names {
		if strings.HasPrefix(name, prefix) {
			j = i
			break
		}
	}
	if j < 0 {
		return []string{}, "", nil
	}

	for i, name := range names[j:] {
		if n > 0 && i+j == n {
			return names[j : j+i], names[i+j], nil
		}
		if !strings.HasPrefix(name, prefix) {
			return names[j : j+i], "", nil
		}
	}
	return names[j:], "", nil
}

func (s *FS) create(filename string, value []byte) error {
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
