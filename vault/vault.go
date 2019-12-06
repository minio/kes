// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

// Package vault implements a secret key store that
// stores secret keys as key-value entries on the
// Hashicorp Vault K/V secret backend.
//
// Vault is a KMS implementation with many featues.
// This packages only leverages the key-value store.
// For an introduction to Vault see: https://www.vaultproject.io/
// For an K/V API overview see: https://www.vaultproject.io/api/secret/kv/kv-v1.html
package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	key "github.com/minio/keys"
	"github.com/minio/keys/internal/cache"
)

// AppRole holds the Vault AppRole
// authentication credentials and
// a duration after which the
// authentication should be retried
// whenever it fails.
type AppRole struct {
	ID     string // The AppRole  ID
	Secret string // The Approle secret ID
	Retry  time.Duration
}

// KeyStore is a secret key store that saves
// secret keys as K/V entries on Vault's K/V
// secret backend.
type KeyStore struct {
	// Addr is the HTTP address of the Vault server.
	Addr string

	// Location is the location on Vault's K/V store
	// where this KeyStore will save secret keys.
	//
	// It can be used to assign an unique or shared
	// prefix. For instance one or more KeyStore can
	// store secret keys under /keys/my-app/. In this
	// case you may set KeyStore.Location = "key/my-app".
	Location string

	// AppRole contains the Vault AppRole authentication
	// credentials.
	AppRole AppRole

	// CacheExpireAfter is the duration after which
	// cache entries expire such that they have to
	// be loaded from the backend storage again.
	CacheExpireAfter time.Duration

	// CacheExpireUnusedAfter is the duration after
	// which not recently used cache entries expire
	// such that they have to be loaded from the
	// backend storage again.
	// Not recently is defined as: CacheExpireUnusedAfter / 2
	CacheExpireUnusedAfter time.Duration

	// StatusPingAfter is the duration after which
	// the KeyStore will check the status of the Vault
	// server. Particularly, this status information
	// is used to determine whether the Vault server
	// has been sealed resp. unsealed again.
	StatusPingAfter time.Duration

	cache cache.Cache
	once  uint32

	client *vaultapi.Client
	sealed bool
}

// Authenticate tries to establish a connection to
// a Vault server using the approle credentials.
// It returns an error if no connection could be
// established - for instance because of invalid
// authentication credentials.
func (store *KeyStore) Authenticate(context context.Context) error {
	client, err := vaultapi.NewClient(&vaultapi.Config{
		Address: store.Addr,
	})
	if err != nil {
		return err
	}
	store.client = client

	status, err := store.client.Sys().Health()
	if err != nil {
		return err
	}
	store.sealed = status.Sealed

	var token string
	var ttl time.Duration
	if !status.Sealed {
		token, ttl, err = store.authenticate(store.AppRole)
		if err != nil {
			return err
		}
		store.client.SetToken(token)
	}

	go store.checkStatus(context, store.StatusPingAfter)
	go store.renewAuthToken(context, store.AppRole, ttl)
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns key.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the corresponding
// entry at the Vault K/V store.
func (store *KeyStore) Get(name string) (key.Secret, error) {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.Secret{}, key.ErrStoreSealed
	}

	store.initialize()
	if secret, ok := store.cache.Get(name); ok {
		return secret, nil
	}

	// Since we haven't found the requested secret key in the cache
	// we reach out to Vault's K/V store and fetch it from there.
	entry, err := store.client.Logical().Read(fmt.Sprintf("/kv/%s/%s", store.Location, name))
	if err != nil || entry == nil {
		// Vault will not return an error if e.g. the key existed but has
		// been deleted. However, it will return (nil, nil) in this case.
		if err == nil && entry == nil {
			return key.Secret{}, key.ErrKeyNotFound
		}
		return key.Secret{}, err
	}

	// Verify that we got a well-formed secret key from Vault
	v, ok := entry.Data[name]
	if !ok || v == nil {
		return key.Secret{}, errors.New("vault: missing secret key")
	}
	s, ok := v.(string)
	if !ok {
		return key.Secret{}, errors.New("vault: malformed secret key")
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(decodedSecret) != 32 {
		return key.Secret{}, errors.New("vault: malformed secret key")
	}

	var secret key.Secret
	copy(secret[:], decodedSecret)
	secret, _ = store.cache.Add(name, secret)
	return secret, nil
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns key.ErrKeyExists.
//
// In particular, Create creates a new K/V entry on the Vault
// key store.
func (store *KeyStore) Create(name string, secret key.Secret) error {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.ErrStoreSealed
	}

	store.initialize()
	if _, ok := store.cache.Get(name); ok {
		return key.ErrKeyExists
	}

	// We try to check whether key exists on the K/V store.
	// If so, we must not overwrite it.
	location := fmt.Sprintf("/kv/%s/%s", store.Location, name)

	// Vault will return nil for the secret as well as a nil-error
	// if the specified entry does not exist.
	// More specifically the Vault server + client behaves as following:
	//  - If the entry does not exist (b/c it never existed) the server
	//    returns 404 and the client returns the tuple (nil, nil).
	//  - If the entry does not exist (b/c it existed before but has
	//    been deleted) the server returns 404 but response with a
	//    "secret". The client will still parse the response body (even
	//    though 404) and return (nil, nil) if the body is empty or
	//    the secret contains no data (and no "warnings" or "errors")
	//
	// Therefore, we check whether the client returns a nil error
	// and a non-nil "secret". In this case, the secret key already
	// exists.
	// But when the client returns an error it does not mean that
	// the entry does not exist but that some other error (e.g.
	// network error) occurred.
	switch s, err := store.client.Logical().Read(location); {
	case err == nil && s != nil:
		return key.ErrKeyExists
	case err != nil:
		return err
	}

	// Finally, we create the secret key since it seems that it
	// doesn't exist. However, this is just an assumption since
	// another key server may have created that key in the meantime.
	// Since there is now way we can detect that reliable we require
	// that whoever has the permission to create keys does that in
	// a non-racy way.
	_, err := store.client.Logical().Write(location, map[string]interface{}{
		name: base64.StdEncoding.EncodeToString(secret[:]),
	})
	if err != nil {
		return err
	}
	store.cache.Set(name, secret)
	return nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the corresponding Vault
// K/V entry, if it exists.
func (store *KeyStore) Delete(name string) error {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.ErrStoreSealed
	}

	// Vault will not return an error if an entry does not
	// exist. Instead, it responds with 204 No Content and
	// no body. In this case the client also returns a nil-error
	// Therefore, we can just try to delete it in any case.
	_, err := store.client.Logical().Delete(fmt.Sprintf("/kv/%s/%s", store.Location, name))
	store.cache.Delete(name)
	return err
}

func (store *KeyStore) authenticate(login AppRole) (token string, ttl time.Duration, err error) {
	secret, err := store.client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   login.ID,
		"secret_id": login.Secret,
	})
	if err != nil || secret == nil {
		if err == nil {
			// TODO: return non-nil error
		}
		return token, ttl, err
	}

	token, err = secret.TokenID()
	if err != nil {
		return token, ttl, err
	}

	ttl, err = secret.TokenTTL()
	if err != nil {
		return token, ttl, err
	}
	return token, ttl, err
}

func (store *KeyStore) checkStatus(ctx context.Context, delay time.Duration) {
	var timer *time.Timer
	for {
		status, err := store.client.Sys().Health()
		if err == nil {
			if !store.sealed && status.Sealed {
				store.cache.Clear()
			}
			store.sealed = status.Sealed
		}

		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (store *KeyStore) renewAuthToken(ctx context.Context, login AppRole, ttl time.Duration) {
	for {
		// If Vault is sealed we have to wait
		// until it is unsealed again.
		// The Vault status is checked by another go routine
		// constantly by querying the Vault health status.
		for store.sealed {
			timer := time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		// If the TTL is 0 we cannot renew the token.
		// Therefore, we try to re-authenticate and
		// get a new token. We repeat that until we
		// successfully authenticate and got a token.
		if ttl == 0 {
			var (
				token string
				err   error
			)
			token, ttl, err = store.authenticate(login)
			if err != nil {
				ttl = 0
				timer := time.NewTimer(login.Retry)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				continue
			}
			store.client.SetToken(token) // SetToken is safe to call from different go routines
		}

		// Now the client has token with a non-zero TTL
		// such tht we can renew it. We repeat that until
		// the renewable process fails once. In this case
		// we try to re-authenticate again.
		timer := time.NewTimer(ttl / 2)
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			secret, err := store.client.Auth().Token().RenewSelf(int(ttl.Seconds()))
			if err != nil || secret == nil {
				break
			}
			if ok, err := secret.TokenIsRenewable(); !ok || err != nil {
				break
			}
			ttl, err := secret.TokenTTL()
			if err != nil || ttl == 0 {
				break
			}
			timer.Reset(ttl / 2)
		}
		ttl = 0
	}
}

func (store *KeyStore) initialize() {
	if atomic.CompareAndSwapUint32(&store.once, 0, 1) {
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}
