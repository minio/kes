// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

// Package mem implements an in-memory secret key store.
package mem

import (
	"context"
	"sync"
	"time"

	"github.com/minio/key"
	"github.com/minio/key/internal/cache"
)

// KeyStore is an in-memory secret key store.
type KeyStore struct {
	// CacheExpireAfter is the duration after which
	// cache entries expire such that they have to
	// be loaded from the backend storage again.
	CacheExpireAfter time.Duration

	// CacheExpireUnusedAfter is the duration after
	// which not recently used cache entries expire
	// such that they have to be loaded from the
	// backend storage again.
	// Not recently is defined as: CacheExpireUnusedAfter / 2
	CacheExpireUnusedAfter time.Duration

	cache cache.Cache

	lock  sync.RWMutex
	store map[string]key.Secret

	once sync.Once // initializes the store and starts cache GCs
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns key.ErrKeyExists.
func (store *KeyStore) Create(name string, secret key.Secret) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache.Get(name); ok {
		return key.ErrKeyExists
	}
	if _, ok := store.store[name]; ok {
		return key.ErrKeyExists
	}
	if store.store == nil {
		store.once.Do(store.initialize)
	}
	store.cache.Set(name, secret)
	store.store[name] = secret
	return nil
}

// Delete removes a the secret key with the given name
// from the key store if it exists.
func (store *KeyStore) Delete(name string) error {
	store.lock.Lock()
	store.cache.Delete(name)
	delete(store.store, name)
	store.lock.Unlock()
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns key.ErrKeyNotFound.
func (store *KeyStore) Get(name string) (key.Secret, error) {
	secret, ok := store.cache.Get(name)
	if ok {
		return secret, nil
	}

	// The secret key is not in the cache.
	// So we check whether it exists at all
	// and, if so, add it to the cache.
	store.lock.Lock()
	defer store.lock.Unlock()

	secret, ok = store.store[name]
	if !ok {
		return key.Secret{}, key.ErrKeyNotFound
	}
	store.cache.Set(name, secret)
	return secret, nil
}

func (store *KeyStore) initialize() {
	// We have to hold the write-lock here
	// since once.Do may modify the in-memory
	// store.
	if store.store == nil {
		store.store = map[string]key.Secret{}
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}
