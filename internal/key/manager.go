package key

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
)

// Typed errors that are returned to the client.
// The errors are generic on purpose to not leak
// any (potentially sensitive) information.
var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Manager is a key manager that fetches keys from a key store
// and caches them in a local in-memory cache.
//
// It runs a garbage collection that periodically removes keys
// from the cache such that they have to be fetched from the key
// store again.
type Manager struct {
	// Store is the key store that persists cryptographic
	// keys. The key manager will fetch the key from it if
	// the key isn't in its cache.
	Store Store

	// CacheExpiryAny is the time period keys remain - at
	// most - in the key manager cache.
	//
	// The key manager will clear the entire cache whenever
	// this time period elapses and will start a new time
	// interval such that the cache get cleared periodically.
	CacheExpiryAny time.Duration

	// CacheExpiryUnused is the time keys remain in the cache
	// even though they are not used.
	//
	// A key that is used before one interval elapses is
	// marked as used again and remains in the cache.
	CacheExpiryUnused time.Duration

	// CacheExpiryOffline is the time keys remain in the
	// offline cache.
	//
	// The offline cache is only used when the Store is
	// not available and CacheExpiryOffline > 0.
	//
	// The offline cache, if used, gets cleared whenever
	// the Store becomes available again.
	CacheExpiryOffline time.Duration

	// CacheContext is the context that controls the cache
	// garbage collection. Once its Done() channel returns,
	// the garbage collection stops.
	CacheContext context.Context

	once         sync.Once // Start the GC only once
	cache        cache
	offlineCache cache

	// Controls whether the offline cache is used:
	//  - 0: Offline cache is disabled
	//  - 1: Offline cache is enabled
	//
	// Concurrently modified when checking the Store
	// status.
	// By default, don't use the offline cache
	useOfflineCache uint32
}

// Create stores the given key at the key store.
//
// If an entry with the same name exists, Create
// returns kes.ErrKeyExists.
func (m *Manager) Create(ctx context.Context, name string, key Key) error {
	switch err := m.Store.Create(ctx, name, key); {
	case err == nil:
		return nil
	case errors.Is(err, kes.ErrKeyExists):
		return kes.ErrKeyExists
	default:
		return errCreateKey
	}
}

// Get returns the key with the given name.
//
// If no key with the given name exists,
// Get returns kes.ErrKeyNotFound.
//
// Get tries to find the key in its cache
// first and fetches the key only from the
// key store if it's not in the cache.
func (m *Manager) Get(ctx context.Context, name string) (Key, error) {
	m.once.Do(m.startGC)
	if key, ok := m.cache.Get(name); ok {
		return key, nil
	}
	if atomic.LoadUint32(&m.useOfflineCache) == 1 {
		if key, ok := m.offlineCache.Get(name); ok {
			return key, nil
		}
	}
	switch key, err := m.Store.Get(ctx, name); {
	case err == nil:
		return m.cache.CompareAndSwap(name, key), nil
	case errors.Is(err, kes.ErrKeyNotFound):
		return Key{}, kes.ErrKeyNotFound
	default:
		return Key{}, errGetKey
	}
}

// Delete deletes the key with the given name
// at the key store.
//
// Delete does not return an error if no key
// with this name exists.
func (m *Manager) Delete(ctx context.Context, name string) error {
	m.once.Do(m.startGC)
	m.cache.Delete(name)
	m.offlineCache.Delete(name)

	switch err := m.Store.Delete(ctx, name); {
	case err == nil:
		return nil
	case errors.Is(err, kes.ErrKeyNotFound):
		return nil
	default:
		return errDeleteKey
	}
}

// List returns an iterator over all keys at the
// key store.
//
// The returned iterator may or may not reflect any
// concurrent changes to the key store - i.e. creates
// or deletes. Further, it does not provide any ordering
// guarantees.
func (m *Manager) List(ctx context.Context) (Iterator, error) {
	iter, err := m.Store.List(ctx)
	if err != nil {
		return nil, errListKey
	}
	return iter, nil
}

func (m *Manager) startGC() {
	var ctx = m.CacheContext
	if ctx == nil {
		ctx = context.Background()
	}
	m.cache.StartGC(ctx, m.CacheExpiryAny)

	// Actually, we also don't run the unused GC if CacheExpiryUnused/2 == 0,
	// not if CacheExpiryUnused == 0.
	// However, that can only happen if CacheExpiryUnused is 1ns - which is
	// anyway an unreasonable value for the expiry.
	m.cache.StartUnusedGC(ctx, m.CacheExpiryUnused/2)

	m.offlineCache.StartGC(ctx, m.CacheExpiryOffline)
	m.watchStatus(ctx, 10*time.Second)
}

func (m *Manager) watchStatus(ctx context.Context, t time.Duration) {
	if t == 0 {
		return
	}

	const (
		Online  = 0
		Offline = 1
	)
	go func() {
		ticker := time.NewTicker(t)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// When the Store status changes from available to
				// unreachable, we load the general cache into the
				// offline cache.
				// Once the Store becomes available again, we clear
				// both caches and start with a clean state.
				state, err := m.Store.Status(ctx)
				if err != nil || state.State != StoreAvailable {
					if atomic.CompareAndSwapUint32(&m.useOfflineCache, Online, Offline) {
						m.cache.lock.Lock()
						m.offlineCache.lock.Lock()

						m.offlineCache.store, m.cache.store = m.cache.store, map[string]*entry{}

						m.cache.lock.Unlock()
						m.offlineCache.lock.Unlock()
					}
				} else if atomic.CompareAndSwapUint32(&m.useOfflineCache, Offline, Online) {
					m.cache.lock.Lock()
					m.offlineCache.lock.Lock()

					m.offlineCache.store, m.cache.store = map[string]*entry{}, map[string]*entry{}

					m.cache.lock.Unlock()
					m.offlineCache.lock.Unlock()
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
