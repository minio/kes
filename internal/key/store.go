// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"context"
	"errors"
	"log"
	"net"
	"net/url"
	"time"
)

// Store is a key store that persists keys that
// are referenced by a unique name.
type Store interface {
	// Status returns the current state of the
	// Store.
	//
	// If Status fails to reach the Store - e.g.
	// due to a network error - it should return
	// a StoreState with StoreUnreachable and no
	// error.
	//
	// Status should return an error whenever it
	// fails to reach the Store but StoreUnreachable
	// is not appropriate to describe the error
	// condition.
	Status(context.Context) (StoreState, error)

	// Create stores the given key at the key store if
	// and only if no entry with the given name exists.
	//
	// If such entry exists, Create returns kes.ErrKeyExists.
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

// StoreState describes the state of a Store.
type StoreState struct {
	// State is the state of the Store. A Store
	// can either be reachable or unreachable.
	State StoreStatus

	// Latency is the time elapsed to reach
	// the Store.
	Latency time.Duration
}

const (
	// StoreAvailable is the state of a Store
	// that is reachable and can serve requests.
	StoreAvailable StoreStatus = "available"

	// StoreReachable is the state of a Store
	// that is reachable but may not be able
	// to serve requests.
	// For example, a Store may be reachable
	// over the network but needs to be
	// initialized or unsealed to serve requests.
	StoreReachable StoreStatus = "reachable"

	// StoreUnreachable is the state of a Store
	// that is not reachable.
	StoreUnreachable StoreStatus = "unreachable"
)

// StoreStatus describes that the state of a Store.
type StoreStatus string

func (s StoreStatus) String() string { return string(s) }

// DialStore dials to the Store at the given endpoint
// and returns a StoreState describing the Store status.
//
// If it succeeds to dial the Store it returns a StoreState
// with the StoreReachable status - never the StoreAvailable
// status.
//
// If endpoint does not contain any URL scheme, DialStore
// uses the https URL scheme as default.
func DialStore(ctx context.Context, endpoint string) (StoreState, error) {
	const (
		HTTPS       = "https://"
		DefaultPort = "443"
	)

	URL, err := url.Parse(endpoint)
	if err != nil {
		return StoreState{}, err
	}
	if URL.Hostname() == "" {
		// If the URL does not contain a hostname
		// the raw endpoint does not contain a
		// scheme. For example: localhost:443
		// instead of https://localhost:443.
		//
		// In this case, we prepend the
		// https:// scheme to obtain the
		// hostname and port later on.
		URL, err = url.Parse(HTTPS + endpoint)
		if err != nil {
			return StoreState{}, err
		}
	}

	var (
		host = URL.Hostname()
		port = URL.Port()
	)
	if port == "" {
		port = DefaultPort
	}

	var (
		d     net.Dialer
		start = time.Now()
	)
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	latency := time.Since(start)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return StoreState{
			State:   StoreUnreachable,
			Latency: latency,
		}, nil
	}
	if err != nil {
		return StoreState{}, err
	}
	defer c.Close()

	return StoreState{
		State:   StoreReachable,
		Latency: latency,
	}, nil
}

// LogStoreStatus periodically fetches the Store status
// and writes a log message whenever the Store is not
// available.
//
// It stops whenever the given Context.Done() channel
// returns.
func LogStoreStatus(ctx context.Context, store Store, interval time.Duration, out *log.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastAvailable time.Time
	for {
		state, err := store.Status(ctx)
		switch {
		case err != nil:
			out.Printf("key: failed to fetch KMS key store status information: %v", err)
		case state.State != StoreAvailable:
			out.Printf("key: KMS key store is %s for %v", state.State, time.Since(lastAvailable).Round(time.Second))
		default:
			lastAvailable = time.Now().UTC()
		}

		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}
