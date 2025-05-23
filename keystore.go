// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/minio/kes/internal/cache"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kms-go/kes"
)

// This key will be predefined in the config file, which will be stored in keystore before server starts
type Key struct {
	Name string // Name of cryptographic key
}

// A KeyStore stores key-value pairs. It provides durable storage for a
// KES server to persist and access keys. A KeyStore may be modified
// concurrently by different go routines.
type KeyStore interface {
	// Closes the key store and releases associated resources,
	// like background go routines, if any.
	io.Closer

	// Status returns the current state of the KeyStore.
	Status(context.Context) (KeyStoreState, error)

	// Create creates a new entry with the given name if and only
	// if no such entry exists.
	// Otherwise, Create returns kes.ErrKeyExists.
	Create(ctx context.Context, name string, value []byte) error

	// Delete removes the entry. It may return either no error or
	// kes.ErrKeyNotFound if no such entry exists.
	Delete(ctx context.Context, name string) error

	// Get returns the value for the given name. It returns
	// kes.ErrKeyNotFound if no such entry exits.
	Get(ctx context.Context, name string) ([]byte, error)

	// List returns the first n key names, that start with the given
	// prefix, and the next prefix from which the listing should
	// continue.
	//
	// It returns all keys with the prefix if n < 0 and less than n
	// names if n is greater than the number of keys with the prefix.
	//
	// An empty prefix matches any key name. At the end of the listing
	// or when there are no (more) keys starting with the prefix, the
	// returned prefix is empty.
	List(ctx context.Context, prefix string, n int) ([]string, string, error)
}

// KeyStoreState is a structure containing information about
// the current state of a KeyStore.
type KeyStoreState struct {
	Latency time.Duration
}

// MemKeyStore is a volatile KeyStore that stores key-value pairs in
// memory. Its zero value is ready and safe to be used concurrently
// from different go routines. It is optimized for reads but not
// well-suited for many writes/deletes.
type MemKeyStore struct {
	keys cache.Cow[string, []byte]
}

var _ KeyStore = (*MemKeyStore)(nil) // compiler check

func (ks *MemKeyStore) String() string { return "In Memory" }

// Status returns the current state of the MemKeyStore.
// It never returns an error.
func (ks *MemKeyStore) Status(context.Context) (KeyStoreState, error) {
	return KeyStoreState{
		Latency: 1 * time.Millisecond,
	}, nil
}

// Create creates a new entry with the given name if and only
// if no such entry exists.
// Otherwise, Create returns kes.ErrKeyExists.
func (ks *MemKeyStore) Create(_ context.Context, name string, value []byte) error {
	if !ks.keys.Add(name, slices.Clone(value)) {
		return kes.ErrKeyExists
	}
	return nil
}

// Delete removes the entry. It may return either no error or
// kes.ErrKeyNotFound if no such entry exists.
func (ks *MemKeyStore) Delete(_ context.Context, name string) error {
	if !ks.keys.Delete(name) {
		return kes.ErrKeyNotFound
	}
	return nil
}

// Get returns the value for the given name. It returns
// kes.ErrKeyNotFound if no such entry exits.
func (ks *MemKeyStore) Get(_ context.Context, name string) ([]byte, error) {
	if val, ok := ks.keys.Get(name); ok {
		return slices.Clone(val), nil
	}
	return nil, kes.ErrKeyNotFound
}

// List returns the first n key names that start with the given
// prefix and the next prefix from which to continue the listing.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is grater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty.
//
// List never returns an error.
func (ks *MemKeyStore) List(_ context.Context, prefix string, n int) ([]string, string, error) {
	if n == 0 {
		return []string{}, prefix, nil
	}

	keys := ks.keys.Keys()
	slices.Sort(keys)

	if prefix == "" {
		if n < 0 || n >= len(keys) {
			return keys, "", nil
		}
		return keys[:n], keys[n], nil
	}

	i := slices.IndexFunc(keys, func(key string) bool { return strings.HasPrefix(key, prefix) })
	if i < 0 {
		return []string{}, "", nil
	}

	for j, key := range keys[i:] {
		if !strings.HasPrefix(key, prefix) {
			return keys[i : i+j], "", nil
		}
		if n > 0 && j == n {
			return keys[i : i+j], key, nil
		}
	}
	return keys[i:], "", nil
}

// Close does nothing and returns no error.
//
// It is implemented to satisfy the KeyStore
// interface.
func (ks *MemKeyStore) Close() error { return nil }

// newCache returns a new keyCache wrapping the KeyStore.
// It caches keys in memory and evicts cache entries based
// on the CacheConfig.
//
// Close the keyCache to release to the stop background
// garbage collector evicting cache entries and release
// associated resources.
func newCache(store KeyStore, conf *CacheConfig) *keyCache {
	ctx, stop := context.WithCancel(context.Background())
	c := &keyCache{
		store: store,
		stop:  stop,
	}

	expiryOffline := conf.ExpiryOffline
	go c.gc(ctx, conf.Expiry, func() {
		if offline := c.offline.Load(); !offline || expiryOffline <= 0 {
			c.cache.DeleteAll()
		}
	})
	go c.gc(ctx, conf.ExpiryUnused/2, func() {
		if offline := c.offline.Load(); !offline || conf.ExpiryOffline <= 0 {
			c.cache.DeleteFunc(func(_ string, e *cacheEntry) bool {
				// We remove an entry if it isn't marked as used.
				// We also change all other entries to unused such
				// that they get evicted on the next GC run unless
				// they're used in between.
				//
				// Therefore, we try to switch the Used flag from
				// true (used) to flase (unused). If this succeeds,
				// the entry was in fact marked as used and must
				// not be removed. Otherwise, the entry wasn't marked
				// as used and we should evict it.
				return !e.Used.CompareAndSwap(true, false)
			})
		}
	})
	go c.gc(ctx, conf.ExpiryOffline, func() {
		if offline := c.offline.Load(); offline && expiryOffline > 0 {
			c.cache.DeleteAll()
		}
	})
	go c.gc(ctx, 10*time.Second, func() {
		_, err := c.store.Status(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			c.offline.Store(true)
		} else {
			c.offline.Store(false)
		}
	})
	return c
}

// keyCache is an in-memory cache for keys fetched from a Keystore.
// A keyCache runs a background garbage collector that periodically
// evicts cache entries based on a CacheConfig.
//
// It uses lock-free concurrency primitives to optimize for fast
// concurrent reads.
type keyCache struct {
	store KeyStore
	cache cache.Cow[string, *cacheEntry]

	// The barrier prevents reading the same key multiple
	// times concurrently from the kv.Store.
	// When a particular key isn't cached, we don't want
	// to fetch it N times given N concurrent requests.
	// Instead, we want the first request to fetch it and
	// all others to wait until the first is done.
	barrier cache.Barrier[string]

	// Controls whether we treat the cache as offline
	// cache (with different GC config).
	offline atomic.Bool
	stop    func() // Stops the GC
}

// A cache entry with a recently used flag.
type cacheEntry struct {
	Key  crypto.KeyVersion
	Used atomic.Bool
}

// Status returns the current state of the underlying KeyStore.
//
// It immediately returns an error if the backend keystore is not
// reachable and offline caching is enabled.
func (c *keyCache) Status(ctx context.Context) (KeyStoreState, error) {
	if c.offline.Load() {
		return KeyStoreState{}, &keystore.ErrUnreachable{Err: errors.New("keystore is offline")}
	}
	return c.store.Status(ctx)
}

// Create creates a new key with the given name if and only if
// no such entry exists. Otherwise, kes.ErrKeyExists is returned.
func (c *keyCache) Create(ctx context.Context, name string, key crypto.KeyVersion) error {
	b, err := crypto.EncodeKeyVersion(key)
	if err != nil {
		return err
	}

	if err = c.store.Create(ctx, name, b); err != nil {
		if errors.Is(err, kes.ErrKeyExists) {
			return kes.ErrKeyExists
		}
	}
	return err
}

// Delete deletes the key from the key store and removes it from the
// cache. It may return either no error or kes.ErrKeyNotFound if no
// such entry exists.
func (c *keyCache) Delete(ctx context.Context, name string) error {
	if err := c.store.Delete(ctx, name); err != nil {
		if errors.Is(err, kes.ErrKeyNotFound) {
			return err
		}
		return err
	}
	c.cache.Delete(name)
	return nil
}

// Get returns the key from the cache. If it key is not in the cache,
// Get tries to fetch it from the key store and put it into the cache.
// If the key is also not found at the key store, it returns
// kes.ErrKeyNotFound.
//
// Get tries to make as few calls to the underlying key store. Multiple
// concurrent Get calls for the same key, that is not in the cache, are
// serialized.
func (c *keyCache) Get(ctx context.Context, name string) (crypto.KeyVersion, error) {
	if entry, ok := c.cache.Get(name); ok {
		entry.Used.Store(true)
		return entry.Key, nil
	}

	// Since the key is not in the cache, we want to fetch it, once.
	// However, we also don't want to block conccurent reads for different
	// key names.
	// Hence, we acquire a lock per key and release it once done.
	c.barrier.Lock(name)
	defer c.barrier.Unlock(name)

	// Check the cache again, a previous request might have fetched the key
	// while we were blocked by the barrier.
	if entry, ok := c.cache.Get(name); ok {
		entry.Used.Store(true)
		return entry.Key, nil
	}

	b, err := c.store.Get(ctx, name)
	if err != nil {
		if errors.Is(err, kes.ErrKeyNotFound) {
			return crypto.KeyVersion{}, kes.ErrKeyNotFound
		}
		return crypto.KeyVersion{}, err
	}

	k, err := crypto.ParseKeyVersion(b)
	if err != nil {
		return crypto.KeyVersion{}, err
	}

	entry := &cacheEntry{
		Key: k,
	}
	entry.Used.Store(true)
	c.cache.Set(name, entry)
	return entry.Key, nil
}

// List returns the first n key names, that start with the given prefix,
// and the next prefix from which the listing should continue.
//
// It returns all keys with the prefix if n < 0 and less then n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty.
func (c *keyCache) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	return c.store.List(ctx, prefix, n)
}

// Close stops the cache's background garbage collector and
// releases associated resources.
func (c *keyCache) Close() error {
	c.stop()
	return c.store.Close()
}

// gc executes f periodically until the ctx.Done() channel returns.
func (c *keyCache) gc(ctx context.Context, interval time.Duration, f func()) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			f()
		case <-ctx.Done():
			return
		}
	}
}
