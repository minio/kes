// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory key-value store.
package mem

import (
	"context"
	"sync"

	"github.com/minio/kes"
	"github.com/minio/kes/kms"
)

// Store is an in-memory key-value store. Its zero value is
// ready to use.
type Store struct {
	lock  sync.RWMutex
	store map[string][]byte
}

var _ kms.Conn = (*Store)(nil)

// Status returns the state of the in-memory key store which is
// always healthy.
func (s *Store) Status(_ context.Context) (kms.State, error) {
	return kms.State{
		Latency: 0,
	}, nil
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
func (s *Store) List(ctx context.Context) (kms.Iter, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	names := make([]string, 0, len(s.store))
	for name := range s.store {
		names = append(names, name)
	}
	return &iterator{
		values: names,
	}, nil
}

type iterator struct {
	values []string
	last   string
}

var _ kms.Iter = (*iterator)(nil)

func (i *iterator) Next() bool {
	if len(i.values) > 0 {
		i.last = i.values[0]
		i.values = i.values[1:]
		return true
	}
	return false
}

func (i *iterator) Name() string { return i.last }

func (*iterator) Close() error { return nil }
