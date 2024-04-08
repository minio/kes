// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cache

import (
	"sync"
)

// A Barrier is a mutual exclusion lock per key K.
//
// The zero value for a Barrier is an unlocked mutex.
//
// A Barrier must not be copied after first use.
type Barrier[K comparable] struct {
	mu   sync.Mutex
	keys map[K]*barrier
}

// Lock locks the key.
//
// If the key is already in use, the calling goroutine
// blocks until the key is available.
func (b *Barrier[K]) Lock(key K) { b.add(key).Lock() }

// Unlock unlocks the key.
// It is a run-time error if the key is not locked on entry
// to Unlock.
//
// A Barrier is not associated with a particular goroutine.
// It is allowed for one goroutine to lock one Barrier key
// and then arrange for another goroutine to unlock this key.
func (b *Barrier[K]) Unlock(key K) { b.remove(key).Unlock() }

// add adds a new barrier for the given key, if non exist,
// or returns the existing barrier.
func (b *Barrier[K]) add(key K) *barrier {
	b.mu.Lock()
	defer b.mu.Unlock()

	m, ok := b.keys[key]
	if !ok {
		if b.keys == nil {
			b.keys = make(map[K]*barrier)
		}
		m = new(barrier)
		b.keys[key] = m
	}

	m.N++
	return m
}

func (b *Barrier[K]) remove(key K) *barrier {
	b.mu.Lock()
	defer b.mu.Unlock()

	m, ok := b.keys[key]
	if !ok {
		// This is the equivalent of calling Unlock
		// on a unlocked sync.Mutex.
		panic("cache: unlock of unlocked Barrier key")
	}
	m.N--

	if m.N == 0 {
		// Once N reaches 0, the barrier can be removed
		// since no goroutine is trying to acquire a lock
		// for this key.
		delete(b.keys, key)
	}
	return m
}

type barrier struct {
	sync.Mutex

	// N is the number of goroutines that have
	// acquired / are trying to acquire the lock.
	N uint
}
