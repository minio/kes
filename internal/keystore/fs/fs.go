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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/kv"
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
// acts as KMS abstraction over a fileystem.
type Store struct {
	dir  string
	lock sync.RWMutex
}

var _ kv.Store[string, []byte] = (*Store)(nil)

// Status returns the current state of the Conn.
//
// In particular, it reports whether the underlying
// filesystem is accessible.
func (s *Store) Status(context.Context) (kv.State, error) {
	start := time.Now()
	if _, err := os.Stat(s.dir); err != nil {
		return kv.State{}, &kv.Unreachable{Err: err}
	}
	return kv.State{
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
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
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
func (s *Store) Delete(_ context.Context, name string) error {
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
func (s *Store) List(ctx context.Context) (kv.Iter[string], error) {
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, err
	}
	return NewIter(ctx, dir), nil
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

// Iter is an iterator over all files within a
// directory. It must be closed to release any
// filesystem resources.
type Iter struct {
	ctx    context.Context
	dir    fs.ReadDirFile
	names  []fs.DirEntry
	err    error
	closed bool
}

var _ kv.Iter[string] = (*Iter)(nil)

// NewIter returns an Iter all files within the given
// directory. The Iter does not iterator recursively
// into subdirectories.
func NewIter(ctx context.Context, dir fs.ReadDirFile) *Iter {
	return &Iter{
		ctx: ctx,
		dir: dir,
	}
}

// Next reports whether there are more directory entries.
// It returns false when there are no more entries, the
// Iter got closed or once it encounters an error.
//
// The name of the next directory entry is availbale via
// the Name method.
func (i *Iter) Next() (string, bool) {
	if i.closed || i.err != nil {
		return "", false
	}
	if len(i.names) > 0 {
		entry := i.names[0]
		i.names = i.names[1:]
		return entry.Name(), true
	}

	if i.ctx != nil {
		select {
		case <-i.ctx.Done():
			if i.err = i.ctx.Err(); i.err == nil {
				i.err = context.Canceled
			}
			return "", false
		default:
		}
	}

	const N = 256
	i.names, i.err = i.dir.ReadDir(N)
	if errors.Is(i.err, io.EOF) {
		i.err = nil
	}
	if i.err != nil {
		i.Close()
		return "", false
	}
	if len(i.names) > 0 {
		entry := i.names[0]
		i.names = i.names[1:]
		return entry.Name(), true
	}
	return "", false
}

// Close closes the Iter and releases and filesystem
// resources back to the OS.
func (i *Iter) Close() error {
	if i.closed {
		return i.err
	}

	i.closed = true
	if err := i.dir.Close(); i.err == nil {
		i.err = err
	}
	return i.err
}

func validName(name string) error {
	if name == "" || strings.IndexFunc(name, func(c rune) bool {
		return c == '/' || c == '\\' || c == '.'
	}) >= 0 {
		return errors.New("fs: key name contains invalid character")
	}
	return nil
}
