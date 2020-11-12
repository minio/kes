// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"context"
	"sync"
	"time"
)

// MaxSize is the max. size of a secret.
// A secret should not be larger than 1 MiB.
//
// Implementions of Remote should use this to limit
// the amount of data they read from the key-value
// store.
const MaxSize = 1 << 20 // 1 MiB

// Remote is a key-value store for secrets
// Therefore, it stores keys and values as
// strings.
//
// Remote is the interface that must be
// implemented by secret store backends,
// like Vault or AWS SecretsManager.
//
// In general, values are not encrypted before
// they are stored at the Remote store. Therefore,
// an implementation must ensure that it:
// •  stores values securely - i.e. encrypt them.
// •  protect any network communication - i.e. via TLS.
type Remote interface {
	// Create creates a new entry under the given
	// key and stores the given key-value pair
	// if and only if no such entry exists.
	//
	// If an entry already exists it does not replace
	// the value but returns kes.ErrKeyExists.
	Create(key, value string) error

	// Delete deletes the entry under the given key,
	// if any. Once an entry has been deleted a new
	// entry with the same key can be created.
	Delete(key string) error

	// Get returns the value associated with the given
	// key. It returns kes.ErrKeyNotFound if no entry
	// for the given key could be found.
	Get(key string) (string, error)

	// List returns a new Iterator over the names of
	// all stored keys.
	List(ctx context.Context) (Iterator, error)
}

// An Iterator iterates over a source of values.
//   for iterator.Next() {
//       _ = iterator.Value()
//   }
//   if err := iterator.Err(); err != nil {
//   }
//
// An Iterator, in general, does not provide any
// guarantees about the order of values or the
// behavior when its underlying source is modified
// concurrently.
type Iterator interface {
	// Next returns true if there is another item.
	// This item can be retrieved via the Value
	// method.
	//
	// It returns false if no more items are available
	// or if the iterator encountered an error. The error,
	// if any, can be retrieved via the Err method.
	Next() bool

	// Value returns the latest value encountered. It
	// returns the same value until Next is called
	// again.
	//
	// If Next returns false then the behavior of a
	// subsequent Value call is implementation-dependent.
	Value() string

	// Err returns the first error encountered by the
	// Iterator, if any.
	Err() error
}

// Store is the local secret store connected
// to a remote key-value store.
//
// It is responsible for caching secrets and
// storing/fetching values to/from the the
// Remote store.
type Store struct {
	// Remote is the remote key-value store. Secrets
	// will be fetched from or written to this store.
	//
	// It must not be modified once the Store has been
	// used to fetch or store secrets.
	Remote Remote

	cache cache
	once  sync.Once // For the cache garbage collection
}

// Create adds the given secret with the given name to
// the secret store. If there is already a secret with
// this name then it does not replace the secret and
// returns kes.ErrKeyExists.
func (s *Store) Create(name string, secret Secret) (err error) {
	if err = s.Remote.Create(name, secret.String()); err != nil {
		return err
	}
	s.cache.SetOrGet(name, secret)
	return nil
}

// Delete deletes the secret associated with the given
// name, if one exists.
func (s *Store) Delete(name string) error {
	// We can always remove a secret from the cache.
	// If the delete operation on the remote store
	// fails we will fetch it again on the next Get.
	s.cache.Delete(name)
	return s.Remote.Delete(name)
}

// Get returns the secret associated with the given name,
// if any. If no such secret exists it returns
// kes.ErrKeyNotFound.
func (s *Store) Get(name string) (Secret, error) {
	if secret, ok := s.cache.Get(name); ok {
		return secret, nil
	}

	value, err := s.Remote.Get(name)
	if err != nil {
		return Secret{}, err
	}
	secret, err := ParseSecret(value)
	if err != nil {
		return Secret{}, err
	}
	return s.cache.SetOrGet(name, secret), nil
}

// List returns a new Iterator over all key names.
//
// The behavior of the Iterator is implementation-specific
// and depends upon the Remote key store backend.
func (s *Store) List(ctx context.Context) (Iterator, error) {
	return s.Remote.List(ctx)
}

// StartGC starts the cache garbage collection background process.
// The GC will discard all cached secrets after expiry. Further,
// it will discard all entries that haven't been used for unusedExpiry.
//
// If expiry is 0 the GC will not discard any secrets. Similarly, if
// the unusedExpiry is 0 then the GC will not discard unused secrets.
//
// There is only one garbage collection background process. Calling
// StartGC more than once has no effect.
func (s *Store) StartGC(ctx context.Context, expiry, unusedExpiry time.Duration) {
	s.once.Do(func() {
		s.cache.StartGC(ctx, expiry)

		// Actually, we also don't run the unused GC if unusedExpiry/2 == 0,
		// not if unusedExpiry == 0.
		// However, that can only happen if unusedExpiry is 1ns - which is
		// anyway an unreasonable value for the expiry.
		s.cache.StartUnusedGC(ctx, unusedExpiry/2)
	})
}
