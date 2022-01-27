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
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
)

// Store is a file system key-value store that stores
// keys as file names in a directory.
type Store struct {
	// Dir is the directory where key-value entries
	// are located. The store will read / write
	// values from / to files in this directory.
	Dir string

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger
}

var _ key.Store = (*Store)(nil)

// Status returns the current state of the FS key store.
func (s *Store) Status(_ context.Context) (key.StoreState, error) {
	state := key.StoreAvailable

	start := time.Now()
	_, err := os.Stat(s.Dir)
	latency := time.Since(start)
	if err != nil {
		state = key.StoreUnreachable
	}
	return key.StoreState{
		State:   state,
		Latency: latency,
	}, nil
}

// Create stores the key in a new file in the KeyStore
// directory if and only if no file with the given name
// does not exists.
//
// If such a file already exists it returns kes.ErrKeyExists.
func (s *Store) Create(_ context.Context, name string, key key.Key) error {
	if err := validatePath(name); err != nil {
		s.logf("fs: invalid key name %q: %v", name, err)
		return err
	}

	// We use os.O_CREATE and os.O_EXCL to enforce that the
	// file must not have existed before.
	path := filepath.Join(s.Dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return kes.ErrKeyExists
	}
	if err != nil {
		s.logf("fs: cannot open %q: %v", path, err)
		return err
	}
	defer file.Close()

	if _, err = file.WriteString(key.String()); err != nil {
		s.logf("fs: failed to write to %q: %v", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			s.logf("fs: cannot remove %q: %v", path, rmErr)
		}
		return err
	}

	if err = file.Sync(); err != nil { // Ensure that we wrote the value to disk
		s.logf("fs: cannot to flush and sync %s: %v", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			s.logf("fs: cannot remove %q: %v", path, rmErr)
		}
		return err
	}
	return nil
}

// Delete removes the file with the given name in the
// KeyStore directory, if it exists. It does not return
// an error if the file does not exist.
func (s *Store) Delete(_ context.Context, name string) error {
	if err := validatePath(name); err != nil {
		s.logf("fs: invalid key name %q: %v", name, err)
		return err
	}

	var (
		path = filepath.Join(s.Dir, name)
		err  = os.Remove(path)
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return kes.ErrKeyNotFound
		}
		s.logf("fs: failed to delete %q: %v", path, err)
		return err
	}
	return nil
}

// Get returns the key associated with the given name. If no
// entry for name exists, Get returns kes.ErrKeyNotFound. In
// particular, Get reads the key from the associated
// file in KeyStore directory.
func (s *Store) Get(_ context.Context, name string) (key.Key, error) {
	if err := validatePath(name); err != nil {
		s.logf("fs: invalid key name %q: %v", name, err)
		return key.Key{}, err
	}

	var (
		path      = filepath.Join(s.Dir, name)
		file, err = os.Open(path)
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return key.Key{}, kes.ErrKeyNotFound
		}
		s.logf("fs: cannot open %q: %v", path, err)
		return key.Key{}, err
	}
	defer file.Close()

	var value strings.Builder
	if _, err := io.Copy(&value, io.LimitReader(file, key.MaxSize)); err != nil {
		s.logf("fs: failed to read from %q: %v", path, err)
		return key.Key{}, err
	}
	k, err := key.Parse(value.String())
	if err != nil {
		s.logf("fs: failed to parse key from %q: %v", path, err)
		return key.Key{}, err
	}
	return k, nil
}

// List returns a new iterator over the metadata of all stored keys.
func (s *Store) List(ctx context.Context) (key.Iterator, error) {
	file, err := os.Open(s.Dir)
	if err != nil {
		s.logf("fs: cannot open %q: %v", s.Dir, err)
		return nil, err
	}
	defer file.Close()

	files, err := file.Readdir(0)
	if err != nil {
		s.logf("fs: failed to list keys: %v", err)
		return nil, err
	}
	return &iterator{
		values: files,
	}, nil
}

type iterator struct {
	values []os.FileInfo
	last   string
}

var _ key.Iterator = (*iterator)(nil)

func (i *iterator) Next() bool {
	for len(i.values) > 0 {
		if i.values[0].Mode().IsRegular() {
			i.last = i.values[0].Name()
			i.values = i.values[1:]
			return true
		}
		i.values = i.values[1:]
	}
	return false
}

func (i *iterator) Name() string { return i.last }

func (*iterator) Err() error { return nil }

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}

// validatePath returns an error of the given key name
// contains a path separator, and therefore, is an
// invalid key name.
//
// Key names that contain path separator(s) are considered
// malicious because they may be abused for directory traversal
// attacks.
func validatePath(name string) error {
	if strings.ContainsRune(name, '/') {
		return errors.New("fs: key name contains path separator")
	}
	if runtime.GOOS == "windows" && strings.ContainsRune(name, '\\') {
		return errors.New("fs: key name contains path separator")
	}
	return nil
}
