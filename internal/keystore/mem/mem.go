// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory key-value store.
package mem

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
)

// Store is an in-memory key-value store. Its zero value is
// ready to use.
type Store struct {
	lock  sync.RWMutex
	store map[string][]byte
}

// Status returns the state of the in-memory key store which is
// always healthy.
func (s *Store) Status(_ context.Context) (edge.KeyStoreState, error) {
	return edge.KeyStoreState{Latency: 0}, nil
}

// Create adds the given key to the store if and only if
// no entry for the given name exists. If an entry already
// exists it returns kes.ErrKeyExists.
func (s *Store) Create(_ context.Context, name string, value []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.store == nil {
		s.store = map[string][]byte{}
	}
	if _, ok := s.store[name]; ok {
		return kes.ErrKeyExists
	}
	s.store[name] = value
	return nil
}

// Set adds the given key to the store if and only if
// no entry for the given name exists. If an entry already
// exists it returns kes.ErrKeyExists.
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
}

// Delete removes the key with the given value, if it exists.
func (s *Store) Delete(_ context.Context, name string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	delete(s.store, name)
	return nil
}

// Get returns the key associated with the given name. If no
// entry for this name exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(_ context.Context, name string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	k, ok := s.store[name]
	if !ok {
		return nil, kes.ErrKeyNotFound
	}
	return k, nil
}

// List returns a new iterator over the metadata of all stored keys.
func (s *Store) List(_ context.Context, prefix string, n int) ([]string, string, error) {
	s.lock.RLock()
	names := make([]string, 0, len(s.store))
	for name := range s.store {
		names = append(names, name)
	}
	s.lock.RUnlock()

	sort.Strings(names)

	first := -1
	for i, name := range names {
		if strings.HasPrefix(name, prefix) {
			first = i
			break
		}
	}
	if first < 0 {
		return []string{}, "", nil
	}
	if n > 0 && first+n < len(names) {
		return names[first : first+n], "", nil
	}
	return names[first:], "", nil
}
