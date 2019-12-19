// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package mem implements an in-memory secret key store.
package mem

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
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

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	cache cache.Cache

	lock  sync.RWMutex
	store map[string]string

	once sync.Once // initializes the store and starts cache GCs
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
func (store *KeyStore) Create(name string, secret kes.Secret) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
	}
	if _, ok := store.store[name]; ok {
		return kes.ErrKeyExists
	}
	if store.store == nil {
		store.once.Do(store.initialize)
	}
	store.cache.Set(name, secret)
	store.store[name] = secret.String()
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
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
func (store *KeyStore) Get(name string) (kes.Secret, error) {
	secret, ok := store.cache.Get(name)
	if ok {
		return secret, nil
	}

	// The secret key is not in the cache.
	// So we check whether it exists at all
	// and, if so, add it to the cache.
	store.lock.Lock()
	defer store.lock.Unlock()

	s, ok := store.store[name]
	if !ok {
		return kes.Secret{}, kes.ErrKeyNotFound
	}
	if err := secret.ParseString(s); err != nil {
		store.logf("mem: failed to read secret '%s': %v", name, err)
		return secret, err
	}
	store.cache.Set(name, secret)
	return secret, nil
}

func (store *KeyStore) initialize() {
	// We have to hold the write-lock here
	// since once.Do may modify the in-memory
	// store.
	if store.store == nil {
		store.store = map[string]string{}
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}

func (store *KeyStore) logf(format string, v ...interface{}) {
	if store.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		store.ErrorLog.Printf(format, v...)
	}
}
