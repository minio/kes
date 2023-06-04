package edge

import (
	"context"
	"time"
)

type KeyStore interface {
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
	Status(context.Context) (KeyStoreState, error)

	// Create creates a new entry at the
	// storage if and only if no entry for
	// the give key exists.
	//
	// If such an entry already exists,
	// Create returns ErrExists.
	Create(context.Context, string, []byte) error

	// Get returns the value associated with
	// the given key.
	//
	// It returns ErrNotExists if no such
	// entry exists.
	Get(context.Context, string) ([]byte, error)

	// Delete deletes the key and the associated
	// value from the storage.
	//
	// It returns ErrNotExists if no such
	// entry exists.
	Delete(context.Context, string) error

	// List returns an Iter enumerating the stored
	// entries.
	List(context.Context, string, int) ([]string, string, error)
}

// State describes the state of a Store.
type KeyStoreState struct {
	// Latency is the connection latency
	// to the Store.
	Latency time.Duration
}
