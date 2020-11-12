// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory key-value store.
package mem

import (
	"context"
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

// List returns a new Iterator over the names of
// all stored keys.
func (s *Store) List(ctx context.Context) (secret.Iterator, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	keys := make([]string, 0, len(s.store))
	for key := range s.store {
		keys = append(keys, key)
	}
	return &iterator{
		values: keys,
	}, nil
}

type iterator struct {
	values []string
	last   string
}

var _ secret.Iterator = (*iterator)(nil)

func (i *iterator) Next() bool {
	if len(i.values) > 0 {
		i.last = i.values[0]
		i.values = i.values[1:]
		return true
	}
	return false
}

func (i *iterator) Value() string { return i.last }

func (*iterator) Err() error { return nil }
