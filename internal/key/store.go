// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"context"
	"errors"
	"log"

	"github.com/minio/kes"
	"github.com/minio/kes/kms"
)

// Store is a key store that reads/writes
// keys from/to a KMS via a kms.Conn.
type Store struct {
	// Conn is the connection to the KMS.
	Conn kms.Conn

	// ErrorLog is an optional Logger for
	// errors that may occur when reading
	// or writing keys from/to the KMS.
	ErrorLog *log.Logger
}

// Status returns the current state of the
// underlying kms.Conn.
//
// Status returns kms.Unreachable when it
// fails to reach the KMS.
func (s *Store) Status(ctx context.Context) (kms.State, error) { return s.Conn.Status(ctx) }

// Create creates a new entry with the the
// given key if and only if no entry for the
// given name exists.
//
// If such an entry already exists, Create
// returns kes.ErrKeyExists.
func (s *Store) Create(ctx context.Context, name string, key Key) error {
	b, err := key.MarshalText()
	if err != nil {
		return err
	}

	err = s.Conn.Create(ctx, name, b)
	if err != nil && !errors.Is(err, kes.ErrKeyExists) {
		logln(s.ErrorLog, err)
	}
	return err
}

// Get returns the key for the given name or
// an error explaining why fetching the key
// from the KMS failed.
//
// If no entry for the given name exists, Get
// returns kes.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, name string) (Key, error) {
	b, err := s.Conn.Get(ctx, name)
	switch {
	case errors.Is(err, kes.ErrKeyNotFound):
		return Key{}, err
	case err != nil:
		logln(s.ErrorLog, err)
		return Key{}, err
	default:
		key, err := Parse(b)
		if err != nil {
			logln(s.ErrorLog, err)
		}
		return key, err
	}
}

// Delete deletes the specified entry at the KMS.
//
// If no entry for the given name exists, Delete
// returns kes.ErrKeyNotFound.
func (s *Store) Delete(ctx context.Context, name string) error {
	err := s.Conn.Delete(ctx, name)
	if err != nil && !errors.Is(err, kes.ErrKeyNotFound) {
		logln(s.ErrorLog, err)
	}
	return err
}

// List returns an iterator over the entries
// at the KMS.
//
// The returned Iter stops fetching entries
// from the KMS once ctx.Done() returns.
func (s *Store) List(ctx context.Context) (kms.Iter, error) {
	iter, err := s.Conn.List(ctx)
	if err != nil {
		logln(s.ErrorLog, err)
	}
	return iter, err
}

func logln(logger *log.Logger, v ...any) {
	if logger == nil {
		log.Println(v...)
	} else {
		logger.Println(v...)
	}
}
