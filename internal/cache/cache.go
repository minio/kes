// Package cache implements an in-memory cache
// for secret keys.
package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aead/key"
)

// An Entry holds a cached secret key and additional
// cache-related metadata. For instance, whether the
// entry has been used recently.
type Entry struct {
	Secret key.Secret

	used *uint32
}

// Cache is a in-memory cache mapping names to
// cache.Entry. It is safe for concurrent use.
type Cache struct {
	lock  sync.RWMutex
	store map[string]Entry
}

// Set adds the given secret key to the cache.
// If there is already an entry for the given
// name then Set replaces this entry.
func (c *Cache) Set(name string, secret key.Secret) {
	var used uint32 = 1

	c.lock.Lock()
	if c.store == nil {
		c.store = map[string]Entry{}
	}
	c.store[name] = Entry{
		Secret: secret,
		used:   &used,
	}
	c.lock.Unlock()
}

// Add adds the given secret key to the cache
// if and only if no entry for name existed
// before. It returns true if and only if no
// entry existed.
//
// In particular, Add returns the secret that
// is in the cache - either the one that existed
// before or the one added by Add.
func (c *Cache) Add(name string, secret key.Secret) (key.Secret, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if entry, ok := c.store[name]; ok {
		return entry.Secret, false
	}

	if c.store == nil {
		c.store = map[string]Entry{}
	}
	var used uint32 = 1
	c.store[name] = Entry{
		Secret: secret,
		used:   &used,
	}
	return secret, true
}

// Get returns the secret key for the
// given name. It returns true if and
// only if a cache entry exists.
func (c *Cache) Get(name string) (key.Secret, bool) {
	c.lock.RLock()
	entry, ok := c.store[name]
	c.lock.RUnlock()

	if ok {
		atomic.StoreUint32(entry.used, 1)
	}
	return entry.Secret, ok
}

// Delete removes the entry with the
// given name if it exists.
func (c *Cache) Delete(name string) {
	c.lock.Lock()
	delete(c.store, name)
	c.lock.Unlock()
}

// Clear removes all entries from the
// cache.
func (c *Cache) Clear() {
	c.lock.Lock()
	c.store = map[string]Entry{}
	c.lock.Unlock()
}

// StartGC spawns a new go-routine that clears
// the cache repeatedly in t intervals.
//
// If t == 0, StartGC does nothing.
func (c *Cache) StartGC(ctx context.Context, t time.Duration) {
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
				c.store = map[string]Entry{}
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
func (c *Cache) StartUnusedGC(ctx context.Context, t time.Duration) {
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
					if !atomic.CompareAndSwapUint32(entry.used, 1, 0) {
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
