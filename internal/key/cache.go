// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/kms"
)

// Typed errors that are returned to the client.
// The errors are generic on purpose to not leak
// any (potentially sensitive) information.
var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// CacheConfig is a structure containing Cache
// configuration options.
type CacheConfig struct {
	// Expiry is the time period keys remain, at
	// most, in the cache.
	Expiry time.Duration

	// ExpiryUnused is the time period keys remain
	// in the cache even though they are not used.
	//
	// A key that is used before one ExpiryUnused
	// interval elapses is marked as used again and
	// remains in the cache.
	ExpiryUnused time.Duration

	// ExpiryOffline is the time keys remain in the
	// offline cache, if enabled.
	//
	// The offline cache is only used when the Store
	// is not available and ExpiryOffline > 0.
	//
	// The offline cache, if enabled, gets cleared
	// whenever the Store becomes available again.
	ExpiryOffline time.Duration
}

// NewCache returns a new Cache that caches keys
// from the Store in memory.
//
// A Cache removes cache entries when they expiry.
// Stop the cache to release associated resources.
func NewCache(store Store, config *CacheConfig) *Cache {
	ctx, cancel := context.WithCancel(context.Background())

	c := &Cache{
		Store:        store,
		cache:        map[string]*cacheEntry{},
		offlineCache: map[string]*cacheEntry{},
		ctx:          ctx,
		cancel:       cancel,
	}
	c.gc(config.Expiry)
	c.gcUnused(config.ExpiryUnused)

	if config.ExpiryOffline > 0 {
		c.gcOffline(config.ExpiryOffline)
		c.watchOfflineStatus(10 * time.Second)
	}
	return c
}

// Cache is a Store that caches keys from an underlying
// Store in memory.
type Cache struct {
	Store Store

	lock         sync.RWMutex
	cache        map[string]*cacheEntry
	offlineCache map[string]*cacheEntry

	// Controls whether the offline cache is used:
	//  - 0: Offline cache is disabled
	//  - 1: Offline cache is enabled
	//
	// Concurrently modified when checking the Store
	// status.
	// By default, not in use
	useOfflineCache uint32

	ctx    context.Context
	cancel context.CancelFunc
}

// var _ Store = (*Cache)(nil) // compiler check

type cacheEntry struct {
	Key Key

	used uint32
}

// Status returns the current state of the Store.
func (c *Cache) Status(ctx context.Context) (kms.State, error) { return c.Store.Status(ctx) }

// Create stors the givem key at the Store if and
// only if no entry with the given name exists.
//
// If such an entry already exists, Create returns
// kes.ErrKeyExists.
func (c *Cache) Create(ctx context.Context, name string, key Key) error {
	switch err := c.Store.Create(ctx, name, key); {
	case err == nil:
		return nil
	case errors.Is(err, kes.ErrKeyExists):
		return kes.ErrKeyExists
	default:
		return errCreateKey
	}
}

// Get returns the key associated with the given name.
// If noc such entry exists, Get returns kes.ErrKeyNotFound.
func (c *Cache) Get(ctx context.Context, name string) (Key, error) {
	if key, ok := c.lookup(c.cache, name); ok {
		return key, nil
	}
	if atomic.LoadUint32(&c.useOfflineCache) == 1 {
		if key, ok := c.lookup(c.offlineCache, name); ok {
			return key, nil
		}
	}
	switch key, err := c.Store.Get(ctx, name); {
	case err == nil:
		return c.insertOrRefresh(c.cache, name, key), nil
	case errors.Is(err, kes.ErrKeyNotFound):
		return Key{}, kes.ErrKeyNotFound
	default:
		return Key{}, errGetKey
	}
}

// Delete deletes the key associated with the given name.
func (c *Cache) Delete(ctx context.Context, name string) error {
	if err := c.Store.Delete(ctx, name); err != nil && !errors.Is(err, kes.ErrKeyNotFound) {
		return errDeleteKey
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.cache, name)
	delete(c.offlineCache, name)
	return nil
}

// List returns a new Iterator over the Store.
func (c *Cache) List(ctx context.Context) (kms.Iter, error) {
	i, err := c.Store.List(ctx)
	if err != nil {
		return nil, errListKey
	}
	return i, nil
}

// Stop stops all background tasks performed by the
// Cache.
func (c *Cache) Stop() { c.cancel() }

// lookup returns the key associated with name in the
// cache. It returns an empty Key and false if there
// is no such entry in the cache.
func (c *Cache) lookup(cache map[string]*cacheEntry, name string) (Key, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	entry, ok := cache[name]
	if !ok {
		return Key{}, false
	}
	atomic.StoreUint32(&entry.used, 1)
	return entry.Key, true
}

// insert inserts the given name / key pair into the
// cache if and only if no such entry exists. Otherwise
// it marks the existing entry as used.
func (c *Cache) insertOrRefresh(cache map[string]*cacheEntry, name string, key Key) Key {
	c.lock.Lock()
	defer c.lock.Unlock()

	if entry, ok := cache[name]; ok {
		atomic.StoreUint32(&entry.used, 1)
		return entry.Key
	}

	cache[name] = &cacheEntry{
		Key:  key,
		used: 1,
	}
	return key
}

// gc spawns a new go-routine that clears
// the cache repeatedly in t intervals.
//
// If t == 0, gc does nothing.
func (c *Cache) gc(t time.Duration) {
	if t == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.lock.Lock()
				c.cache = map[string]*cacheEntry{}
				c.lock.Unlock()
			}
		}
	}()
}

// gcUnused spawns a new go-routine that:
//  1. Removes all entries that are marked
//     as not recently used.
//  2. Marks all remaining entries as not
//     recently used.
//
// The spawned go-routine repeats these two steps
// in t intervals.
//
// In particular, the go-routine removes entries
// only if they haven't been used since it marked
// them unused. Therefore, if unused cache entries
// should survive x seconds, you should set t = x/2.
//
// If t == 0, gcUnused does nothing.
func (c *Cache) gcUnused(t time.Duration) {
	if t == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				var names []string

				c.lock.RLock()
				for name, entry := range c.cache {
					// We check whether Used == 1. If so,
					// we mark it as "to delete on next iteration
					// if not used in between" by setting it to 0.
					// If Used != 1 we consider this as "not used
					// since we marked as to delete". Therefore,
					// we add it to the list of entries that should
					// be deleted.
					if !atomic.CompareAndSwapUint32(&entry.used, 1, 0) {
						names = append(names, name)
					}
				}
				c.lock.RUnlock()

				// Now delete all "expired" entries.
				c.lock.Lock()
				for _, name := range names {
					delete(c.cache, name)
				}
				c.lock.Unlock()
			}
		}
	}()
}

// gc spawns a new go-routine that clears
// the offlineCache repeatedly in t intervals.
//
// If t == 0, gc does nothing.
func (c *Cache) gcOffline(t time.Duration) {
	if t == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-ticker.C:
				c.lock.Lock()
				c.offlineCache = map[string]*cacheEntry{}
				c.lock.Unlock()
			}
		}
	}()
}

// watchOfflineStatus fetches the Store status in
// t intervals. Once the store becomes unavailable,
// it enables the offline cache. Once the store
// becomes available again, it disables the offline
// cache again.
func (c *Cache) watchOfflineStatus(t time.Duration) {
	if t == 0 {
		return
	}

	const (
		Online  = 0
		Offline = 1
	)
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// When the Store status changes from available to
				// unreachable, we load the general cache into the
				// offline cache.
				// Once the Store becomes available again, we clear
				// both caches and start with a clean state.
				_, err := c.Store.Status(c.ctx)
				if err != nil {
					if atomic.CompareAndSwapUint32(&c.useOfflineCache, Online, Offline) {
						c.lock.Lock()
						c.offlineCache, c.cache = c.cache, map[string]*cacheEntry{}
						c.lock.Unlock()

					}
				} else if atomic.CompareAndSwapUint32(&c.useOfflineCache, Offline, Online) {
					c.lock.Lock()
					c.offlineCache, c.cache = map[string]*cacheEntry{}, map[string]*cacheEntry{}
					c.lock.Unlock()
				}
			case <-c.ctx.Done():
				return
			}
		}
	}()
}
