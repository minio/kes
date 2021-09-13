package key

import (
	"context"
)

// Store is a key store that persists keys that
// are referenced by a unique name.
type Store interface {
	// Create stores the given key at the key store if
	// and only if no entry with the given name exists.
	//
	// If no such entry exists, Create returns kes.ErrKeyExists.
	Create(ctx context.Context, name string, key Key) error

	// Delete deletes the key associated with the given name
	// from the key store. It may not return an error if no
	// entry for the given name exists.
	Delete(ctx context.Context, name string) error

	// Get returns the key associated with the given name.
	//
	// If there is no such entry, Get returns kes.ErrKeyNotFound.
	Get(ctx context.Context, name string) (Key, error)

	// List returns a new Iterator over the key store.
	//
	// The returned iterator may or may not reflect any
	// concurrent changes to the key store - i.e. creates
	// or deletes. Further, it does not provide any ordering
	// guarantees.
	List(context.Context) (Iterator, error)
}

// Iterator iterates over the names of set of cryptographic keys.
//   for iterator.Next() {
//       _ := iterator.Name() // Get the name of the key
//   }
//   if err := iterator.Err(); err != nil { // error handling
//   }
//
// Iterator implementations may or may not reflect concurrent
// changes to the set of keys they iterate over. Further, they
// do not guarantee any ordering.
type Iterator interface {
	// Next moves the iterator to the next key, if any.
	// This key is available until Next is called again.
	//
	// It returns true if and only if there is a new key
	// available. If there are no more keys or an error
	// has been encountered, Next returns false.
	Next() bool

	// Name returns the name of the current key. Name
	// can be called multiple times an returns the
	// same value until Next is called again.
	Name() string

	// Err returns the first error, if any, encountered
	// while iterating over the set of keys.
	Err() error
}
