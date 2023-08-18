// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keystore

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cache"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/kv"
)

// CacheConfig is a structure containing Cache
// configuration options.
type CacheConfig struct {
	// Expiry is the time period keys remain, at
	// most, in the Cache.
	//
	// The zero value means keys never expire.
	Expiry time.Duration

	// ExpiryUnused is the time period keys remain
	// in the cache even though they are not used.
	//
	// A key that is used before one ExpiryUnused
	// interval elapses is marked as used again and
	// remains in the cache.
	//
	// The zero value means unused keys never expire.
	ExpiryUnused time.Duration

	// ExpiryOffline is the time keys remain in the
	// Cache, if the underlying kv.Store is offline.
	//
	// Offline caching is only used when the kv.Store
	// is not available and ExpiryOffline > 0.
	ExpiryOffline time.Duration
}

// NewCache returns a new Cache wrapping the store.
//
// It uses the cache expiry configuration to clean
// up cache entries periodically.
//
// The Cache stops its periodic cleanup tasks once
// the ctx.Done channel returns or Stop is called;
// whatever happens first.
func NewCache(ctx context.Context, store kv.Store[string, []byte], config *CacheConfig) *Cache {
	ctxGC, cancelGC := context.WithCancel(ctx)
	c := &Cache{
		store:    store,
		cancelGC: cancelGC,
	}

	go c.gc(ctxGC, config.Expiry, func() {
		if offline := c.offline.Load(); !offline {
			c.cache.DeleteAll()
		}
	})
	go c.gc(ctxGC, config.ExpiryUnused/2, func() {
		if offline := c.offline.Load(); !offline {
			c.cache.DeleteFunc(func(_ string, e *entry) bool {
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
	go c.gc(ctxGC, config.ExpiryOffline, func() {
		if offline := c.offline.Load(); offline {
			c.cache.DeleteAll()
		}
	})
	go c.gc(ctxGC, 10*time.Second, func() {
		_, err := c.store.Status(ctxGC)
		if err != nil && !errors.Is(err, context.Canceled) {
			c.offline.Store(true)
		} else {
			c.offline.Store(false)
		}
	})
	return c
}

// A Cache caches keys in memory.
type Cache struct {
	store kv.Store[string, []byte]
	cache cache.Cow[string, *entry]

	// The barrier prevents reading the same key multiple
	// times concurrently from the kv.Store.
	// When a particular key isn't cached, we don't want
	// to fetch it N times given N concurrent requests.
	// Instead, we want the first request to fetch it and
	// all others to wait until the first is done.
	barrier cache.Barrier[string]

	// Controls whether we treat the cache as offline
	// cache (with different GC config).
	offline  atomic.Bool
	cancelGC func() // Stops the GC
}

var _ kv.Store[string, key.Key] = (*Cache)(nil)

// Stop stops all go routines that periodically
// remove entries from the Cache.
func (c *Cache) Stop() { c.cancelGC() }

// Status returns the current state of the underlying
// kv.Store.
func (c *Cache) Status(ctx context.Context) (kv.State, error) {
	return c.store.Status(ctx)
}

// Create creates a new entry at the underlying kv.Store
// if and only if no entry for the given name exists.
//
// If such an entry already exists, Create returns ErrExists.
func (c *Cache) Create(ctx context.Context, name string, key key.Key) error {
	b, err := key.MarshalText()
	if err != nil {
		log.Printf("keystore: failed to encode key '%s': %v", name, err)
		return errCreateKey
	}

	if err = c.store.Create(ctx, name, b); err != nil {
		if errors.Is(err, kes.ErrKeyExists) {
			return kes.ErrKeyExists
		}
		log.Printf("keystore: failed to create key '%s': %v", name, err)
		return errCreateKey
	}
	return err
}

// Set creates a new entry at the underlying kv.Store if and
// only if no entry for the given name exists.
//
// If such an entry already exists, Set returns ErrExists.
func (c *Cache) Set(ctx context.Context, name string, key key.Key) error {
	return c.Create(ctx, name, key)
}

// Delete deletes the key from the underlying kv.Store.
//
// It returns ErrNotExists if no such entry exists.
func (c *Cache) Delete(ctx context.Context, name string) error {
	if err := c.store.Delete(ctx, name); err != nil {
		if errors.Is(err, kes.ErrKeyNotFound) {
			return err
		}
		log.Printf("keystore: failed to delete key '%s': %v", name, err)
		return errDeleteKey
	}

	c.cache.Delete(name)
	return nil
}

// List returns an Iter enumerating the stored keys.
func (c *Cache) List(ctx context.Context) (kv.Iter[string], error) {
	iter, err := c.store.List(ctx)
	if err != nil {
		log.Printf("keystore: failed to list keys: %v", err)
		return nil, errListKey
	}
	return iter, nil
}

// Get returns the requested key. Get only fetches the key from the
// underlying kv.Store if it isn't in the Cache.
//
// It returns ErrNotExists if no such entry exists.
func (c *Cache) Get(ctx context.Context, name string) (key.Key, error) {
	if entry, ok := c.cache.Get(name); ok {
		entry.Used.Store(true)
		return entry.Key, nil
	}

	// Since the key is not in the cache, we want to fetch - but just once.
	// However, we also don't want to block conccurent reads for different
	// names.
	// Hence, we accquire a lock per key and release it once done.
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
			return key.Key{}, kes.ErrKeyNotFound
		}
		log.Printf("keystore: failed to fetch key '%s': %v", name, err)
		return key.Key{}, errGetKey
	}

	k, err := key.Parse(b)
	if err != nil {
		log.Printf("keystore: failed to fetch key '%s': %v", name, err)
		return key.Key{}, errGetKey
	}

	e := &entry{
		Key: k,
	}
	e.Used.Store(true)
	c.cache.Set(name, e)
	return k, nil
}

// gc executes f periodically until the ctx.Done() channel returns.
func (c *Cache) gc(ctx context.Context, interval time.Duration, f func()) {
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

// A cache entry with a recently used flag.
type entry struct {
	Key  key.Key
	Used atomic.Bool
}

// Typed errors that are returned to the client.
// The errors are generic on purpose to not leak
// any (potentially sensitive) information.
var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)
