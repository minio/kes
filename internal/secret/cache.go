// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// An entry holds a cached secret and additional
// cache-related metadata. For instance, whether
// the entry has been used recently.
type entry struct {
	Secret Secret

	used uint32
}

// cache is a in-memory cache mapping names to
// cache entries. It is safe for concurrent use.
type cache struct {
	lock  sync.RWMutex
	store map[string]*entry
}

// Set adds the given secret to the cache.
// If there is already an entry for the given
// name then Set replaces this entry.
func (c *cache) Set(name string, secret Secret) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.store == nil {
		c.store = map[string]*entry{}
	}
	c.store[name] = &entry{
		Secret: secret,
		used:   1,
	}
}

// SetOrGet adds  given secret to the cache
// if and only if no entry for name already
// exists. Instead, if an entry for the given
// name exists it returns the secret that is
// currently present.
//
// SetOrGet will always return the secret that
// is in the cache right now - either the given
// one or the one that has been there before.
func (c *cache) SetOrGet(name string, secret Secret) Secret {
	c.lock.Lock()
	defer c.lock.Unlock()

	if entry, ok := c.store[name]; ok {
		atomic.StoreUint32(&entry.used, 1)
		return entry.Secret
	}

	if c.store == nil {
		c.store = map[string]*entry{}
	}
	c.store[name] = &entry{
		Secret: secret,
		used:   1,
	}
	return secret
}

// Get returns the secret for the given name.
// It returns true if and only if a cache entry
// exists.
func (c *cache) Get(name string) (Secret, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	entry, ok := c.store[name]
	if !ok {
		return Secret{}, ok
	}
	atomic.StoreUint32(&entry.used, 1)
	return entry.Secret, ok
}

// Delete removes the entry with the
// given name if it exists.
func (c *cache) Delete(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.store, name)
}

// StartGC spawns a new go-routine that clears
// the cache repeatedly in t intervals.
//
// If t == 0, StartGC does nothing.
func (c *cache) StartGC(ctx context.Context, t time.Duration) {
	if t == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.lock.Lock()
				c.store = map[string]*entry{}
				c.lock.Unlock()
			}
		}
	}()
}

// StartUnusedGC spawns a new go-routine that:
//   1. Removes all entries that are marked
//      as not recently used.
//   2. Marks all remaining entries as not
//      recently used.
// The spawned go-routine repeats these two steps
// in t intervals.
//
// In particular, the go-routine removes entries
// only if they haven't been used since it marked
// them unused. Therefore, if unused cache entries
// should survive x seconds, you should set t = x/2.
//
// If t == 0, StartUnusedGC does nothing.
func (c *cache) StartUnusedGC(ctx context.Context, t time.Duration) {
	if t == 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				var names []string

				c.lock.RLock()
				for name, entry := range c.store {
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
					delete(c.store, name)
				}
				c.lock.Unlock()
			}
		}
	}()
}
