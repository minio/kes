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
	"github.com/minio/kes"
	"github.com/minio/kes/kms"
)

// NewConn returns a new Conn that reads
// from and writes to the given directory.
//
// If the directory or any parent directory
// does not exist, NewConn creates them all.
//
// It returns an error if dir exists but is
// not a directory.
func NewConn(dir string) (*Conn, error) {
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
	return &Conn{dir: dir}, nil
}

// Conn is a connection to a directory on
// the filesystem.
//
// It implements the kms.Conn interface and
// acts as KMS abstraction over a fileystem.
type Conn struct {
	dir  string
	lock sync.RWMutex
}

var _ kms.Conn = (*Conn)(nil)

// Status returns the current state of the Conn.
//
// In particular, it reports whether the underlying
// filesystem is accessible.
func (c *Conn) Status(context.Context) (kms.State, error) {
	start := time.Now()
	if _, err := os.Stat(c.dir); err != nil {
		return kms.State{}, &kms.Unreachable{Err: err}
	}
	return kms.State{
		Latency: time.Since(start),
	}, nil
}

// Create creates a new file with the given name inside
// the Conn directory if and only if no such file exists.
//
// It returns kes.ErrKeyExists if such a file already exists.
func (c *Conn) Create(_ context.Context, name string, value []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	c.lock.Lock()
	defer c.lock.Unlock()

	filename := filepath.Join(c.dir, name)
	switch err := c.create(filename, value); {
	case errors.Is(err, os.ErrExist):
		return kes.ErrKeyExists
	case err != nil:
		os.Remove(filename)
		return err
	}
	return nil
}

// Get reads the content of the named file within the Conn
// directory. It returns kes.ErrKeyNotFound if no such file
// exists.
func (c *Conn) Get(_ context.Context, name string) ([]byte, error) {
	const MaxSize = 1 * mem.MiB

	if err := validName(name); err != nil {
		return nil, err
	}
	c.lock.RLock()
	defer c.lock.RUnlock()

	file, err := os.Open(filepath.Join(c.dir, name))
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
func (c *Conn) Delete(_ context.Context, name string) error {
	if err := validName(name); err != nil {
		return err
	}
	switch err := os.Remove(filepath.Join(c.dir, name)); {
	case errors.Is(err, os.ErrNotExist):
		return kes.ErrKeyNotFound
	default:
		return err
	}
}

// List returns a Iter over the files within the Conn directory.
// The Iter must be closed to release any filesystem resources
// back to the OS.
func (c *Conn) List(ctx context.Context) (kms.Iter, error) {
	dir, err := os.Open(c.dir)
	if err != nil {
		return nil, err
	}
	return NewIter(ctx, dir), nil
}

func (c *Conn) create(filename string, value []byte) error {
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
	ctx     context.Context
	dir     fs.ReadDirFile
	entries []fs.DirEntry
	current fs.DirEntry
	err     error
	closed  bool
}

var _ kms.Iter = (*Iter)(nil)

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
func (i *Iter) Next() bool {
	if i.closed || i.err != nil {
		return false
	}
	if len(i.entries) > 0 {
		i.current, i.entries = i.entries[0], i.entries[1:]
		return true
	}

	if i.ctx != nil {
		select {
		case <-i.ctx.Done():
			if i.err = i.ctx.Err(); i.err == nil {
				i.err = context.Canceled
			}
			return false
		default:
		}
	}

	const N = 256
	switch entries, err := i.dir.ReadDir(N); {
	case errors.Is(err, io.EOF):
		i.err = i.Close()
		return false
	case err != nil:
		i.err = err
		return false
	case len(entries) == 0:
		i.err = i.Close()
		return false
	default:
		i.current, i.entries = entries[0], entries[1:]
		return true
	}
}

// Name returns the current name of the directory entry.
// It returns the empty string if there are no more
// entries or once the Iter has encountered an error.
func (i *Iter) Name() string {
	if i.current != nil && !i.closed && i.err == nil {
		return i.current.Name()
	}
	return ""
}

// Close closes the Iter and releases and filesystem
// resources back to the OS.
func (i *Iter) Close() error {
	if i.closed {
		return i.err
	}

	i.closed = true
	err := i.dir.Close()
	if i.err != nil {
		return i.err
	}
	i.err = err
	return err
}

func validName(name string) error {
	if name == "" || strings.IndexFunc(name, func(c rune) bool {
		return c == '/' || c == '\\' || c == '.'
	}) >= 0 {
		return errors.New("fs: key name contains invalid character")
	}
	return nil
}
