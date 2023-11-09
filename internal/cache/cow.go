// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cache

import (
	"sync"
	"sync/atomic"
)

// NewCow returns a new copy-on-write cache with the
// given capacity that can hold at most N entries at
// the same time; N being the capacity.
func NewCow[K comparable, V any](capacity int) *Cow[K, V] {
	c := &Cow[K, V]{
		ptr:      atomic.Pointer[map[K]V]{},
		capacity: capacity,
	}
	c.ptr.Store(&map[K]V{})
	return c
}

// Cow is a copy-on-write cache.
//
// A Cow is optimized for many concurrent reads
// since any read operation does not require a
// lock.
//
// However, a Cow is not well suited for frequent
// updates since it applies changes to a new copy.
//
// The zero Cow is empty and ready for use.
// A Cow must not be copied after first use.
type Cow[K comparable, V any] struct {
	mu       sync.Mutex
	ptr      atomic.Pointer[map[K]V]
	capacity int
}

// Get returns the value associated with the given
// key, if any, and reports whether a value has
// been found.
func (c *Cow[K, V]) Get(key K) (v V, ok bool) {
	m := c.ptr.Load()
	if m == nil {
		return
	}
	v, ok = (*m)[key]
	return
}

// Set adds the key value pair, or replaces an
// existing value. It reports whether the
// given value has been stored.
//
// If the Cow has reached its capacity limit,
// if set, Set does not add the value and
// returns false. However, it still replaces
// existing values, since this does not increase
// the size of the Cow.
func (c *Cow[K, V]) Set(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.ptr.Load()
	if p == nil {
		c.ptr.Store(&map[K]V{key: value})
		return true
	}

	r := *p
	size := len(r)
	if c.capacity > 0 && size >= c.capacity {
		if _, ok := r[key]; !ok {
			return false
		}
	} else {
		size++
	}

	w := make(map[K]V, size)
	for k, v := range r {
		w[k] = v
	}
	w[key] = value

	c.ptr.Store(&w)
	return true
}

// Add adds the value if and only if no
// such entry already exists, and reports
// whether the value has been added.
//
// As long as the Cow has reached its
// capacity limit, if set, Add does not
// add the value and returns false.
func (c *Cow[K, V]) Add(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.ptr.Load()
	if p == nil {
		c.ptr.Store(&map[K]V{key: value})
		return true
	}

	r := *p
	if c.capacity > 0 && len(r) >= c.capacity {
		return false
	}
	if _, ok := r[key]; ok {
		return false
	}

	w := make(map[K]V, len(r)+1)
	for k, v := range r {
		w[k] = v
	}
	w[key] = value

	c.ptr.Store(&w)
	return true
}

// Delete removes the given entry and reports
// whether it was present.
func (c *Cow[K, V]) Delete(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.ptr.Load()
	if p == nil {
		return false
	}

	r := *p
	if len(r) == 0 {
		return false
	}
	if _, ok := r[key]; !ok {
		return false
	}

	w := make(map[K]V, len(r))
	for k, v := range r {
		w[k] = v
	}
	delete(w, key)

	c.ptr.Store(&w)
	return true
}

// DeleteAll removes all entries.
func (c *Cow[K, V]) DeleteAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ptr.Load() != nil {
		c.ptr.Store(new(map[K]V))
	}
}

// DeleteFunc calls f for each entry and removes any
// entry for which f returns true
func (c *Cow[K, V]) DeleteFunc(f func(K, V) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.ptr.Load()
	if p == nil {
		return
	}

	r := *p
	w := make(map[K]V, len(r)/2)
	for k, v := range r {
		if !f(k, v) {
			w[k] = v
		}
	}

	c.ptr.Store(&w)
}

// Clone returns a copy of the Cow.
func (c *Cow[K, V]) Clone() *Cow[K, V] {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.ptr.Load()
	if p == nil {
		return &Cow[K, V]{
			ptr:      atomic.Pointer[map[K]V]{},
			capacity: c.capacity,
		}
	}

	r := *p
	w := make(map[K]V, len(r))
	for k, v := range r {
		w[k] = v
	}

	cc := &Cow[K, V]{
		ptr:      atomic.Pointer[map[K]V]{},
		capacity: c.capacity,
	}
	cc.ptr.Store(&w)
	return cc
}

// Keys returns a slice of all keys of the Cow.
// It never returns nil.
func (c *Cow[K, _]) Keys() []K {
	p := c.ptr.Load()
	if p == nil || len(*p) == 0 {
		return []K{}
	}

	keys := make([]K, 0, len(*p))
	for k := range *p {
		keys = append(keys, k)
	}
	return keys
}
