package key

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type cache struct {
	lock  sync.RWMutex
	store map[string]*entry
}

func (c *cache) Get(name string) (Key, bool) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	entry, ok := c.store[name]
	if !ok {
		return Key{}, false
	}
	atomic.StoreUint32(&entry.used, 1)
	return entry.Key, true
}

func (c *cache) CompareAndSwap(name string, key Key) Key {
	c.lock.Lock()
	defer c.lock.Unlock()

	if entry, ok := c.store[name]; ok {
		atomic.StoreUint32(&entry.used, 1)
		return entry.Key
	}

	if c.store == nil {
		c.store = map[string]*entry{}
	}
	c.store[name] = &entry{
		Key:  key,
		used: 1,
	}
	return key
}

func (c *cache) Delete(name string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.store, name)
}

type entry struct {
	Key Key

	used uint32
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
