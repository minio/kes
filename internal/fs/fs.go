// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package fs implements a key-value store that
// stores keys as file names and values as file
// content.
package fs

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
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

var _ secret.Remote = (*Store)(nil)

// Create creates a new file in the directory if no file
// with the name 'key' does not exists and writes value
// to it.
// If such a file already exists it returns kes.ErrKeyExists.
func (s *Store) Create(key, value string) error {
	// We use os.O_CREATE and os.O_EXCL to enforce that the
	// file must not have existed before.
	path := filepath.Join(s.Dir, key)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil && os.IsExist(err) {
		return kes.ErrKeyExists
	}
	if err != nil {
		s.logf("fs: cannot open %s: %v", path, err)
		return err
	}
	defer file.Close()

	if _, err = file.WriteString(value); err != nil {
		s.logf("fs: failed to write to %s: %v", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			s.logf("fs: cannot remove %s: %v", path, rmErr)
		}
		return err
	}

	if err = file.Sync(); err != nil { // Ensure that we wrote the value to disk
		s.logf("fs: cannot to flush and sync %s: %v", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			s.logf("fs: cannot remove %s: %v", path, rmErr)
		}
		return err
	}
	return nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the associated file,
// if it exists.
func (s *Store) Delete(key string) error {
	path := filepath.Join(s.Dir, key)
	err := os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		err = nil // Ignore the error if the file does not exist
	}
	if err != nil {
		s.logf("fs: failed to delete '%s': %v", path, err)
	}
	return err
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the associated
// file in KeyStore.Dir.
func (s *Store) Get(key string) (string, error) {
	path := filepath.Join(s.Dir, key)
	file, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return "", kes.ErrKeyNotFound
	}
	if err != nil {
		s.logf("fs: cannot open '%s': %v", path, err)
		return "", err
	}
	defer file.Close()

	var value strings.Builder
	if _, err := io.Copy(&value, io.LimitReader(file, secret.MaxSize)); err != nil {
		s.logf("fs: failed to read from '%s': %v", path, err)
		return "", err
	}
	return value.String(), nil
}

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}
