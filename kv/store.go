// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package kv provides abstractions over key-value based
// storage.
package kv

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrExists is returned by a Store when trying to create
	// an entry but the key already exists.
	ErrExists = errors.New("kv: key already exists")

	// ErrNotExists is returned by a Store when trying to
	// access an entry but the key does not exist.
	ErrNotExists = errors.New("kv: key does not exist")
)

// Store stores key-value pairs.
//
// Multiple goroutines may invoke methods
// on a Store simultaneously.
type Store[K comparable, V any] interface {
	// Status returns the current state of the
	// Store or an error explaining why fetching
	// status information failed.
	//
	// Status returns Unreachable when it fails
	// to reach the storage.
	//
	// Status returns Unavailable when it reached
	// the store but the storage is currently not
	// able to process any requests or load/store
	// entries.
	Status(context.Context) (State, error)

	// Create creates a new entry at the
	// storage if and only if no entry for
	// the give key exists.
	//
	// If such an entry already exists,
	// Create returns ErrExists.
	Create(context.Context, K, V) error

	// Set writes the key-value pair to the
	// storage.
	//
	// The store may return ErrExists if such
	// an entry already exists. Further, if
	// no such entry exists, Set may return
	// ErrNotExists to signal that an entry
	// has to be created first.
	Set(context.Context, K, V) error

	// Get returns the value associated with
	// the given key.
	//
	// It returns ErrNotExists if no such
	// entry exists.
	Get(context.Context, K) (V, error)

	// Delete deletes the key and the associated
	// value from the storage.
	//
	// It returns ErrNotExists if no such
	// entry exists.
	Delete(context.Context, K) error

	// List returns an Iter enumerating the stored
	// entries.
	List(context.Context) (Iter[K], error)
}

// Iter iterates over a list of keys.
//
// Its Next method returns the next key
// and a bool indicating whether there
// are more entries.
//
// An Iter should be closed to release
// associated resources.
type Iter[K any] interface {
	// Next returns the next entry, if any,
	// and a bool indicating whether the
	// end of the Iter has been reached.
	//
	// After Next returns false, the Close
	// method returns any error occurred
	// while iterating.
	Next() (K, bool)

	// Close closes the Iter and releases
	// associated resources.
	//
	// It returns either the first error
	// encountered during iterating, if
	// any, or any error that occurrs in
	// the closing process.
	Close() error
}

// State describes the state of a Store.
type State struct {
	// Latency is the connection latency
	// to the Store.
	Latency time.Duration
}
