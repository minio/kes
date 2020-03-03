// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory key-value store.
package mem

import (
	"sync"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
)

// Store is an in-memory key-value store. Its zero value is
// ready to use.
type Store struct {
	lock  sync.RWMutex
	store map[string]string
}

var _ secret.Remote = (*Store)(nil)

// Create adds the given key-value pair to the store if and
// only if no entry for key exists. If an entry already exists
// it returns kes.ErrKeyExists.
func (s *Store) Create(key, value string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.store == nil {
		s.store = map[string]string{}
	}
	if _, ok := s.store[key]; ok {
		return kes.ErrKeyExists
	}
	s.store[key] = value
	return nil
}

// Delete removes the value for the given key, if it exists.
func (s *Store) Delete(key string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.store, key)
	return nil
}

// Get returns the value associated with the given key. If no
// entry for key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(key string) (string, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	value, ok := s.store[key]
	if !ok {
		return "", kes.ErrKeyNotFound
	}
	return value, nil
}
