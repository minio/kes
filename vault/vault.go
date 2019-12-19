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
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
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

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	// Path to the mTLS client private key to authenticate to
	// the Vault server.
	ClientKeyPath string

	// Path to the mTLS client certificate to authenticate to
	// the Vault server.
	ClientCertPath string

	// Path to the root CA certificate(s) used to verify the
	// TLS certificate of the Vault server. If empty, the
	// host's root CA set is used.
	CAPath string

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
	tlsConfig := &vaultapi.TLSConfig{
		ClientKey:  store.ClientKeyPath,
		ClientCert: store.ClientCertPath,
	}
	if store.CAPath != "" {
		stat, err := os.Stat(store.CAPath)
		if err != nil {
			return fmt.Errorf("Failed to open '%s': %v", store.CAPath, err)
		}
		if stat.IsDir() {
			tlsConfig.CAPath = store.CAPath
		} else {
			tlsConfig.CACert = store.CAPath
		}
	}

	config := vaultapi.DefaultConfig()
	config.Address = store.Addr
	config.ConfigureTLS(tlsConfig)
	client, err := vaultapi.NewClient(config)
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
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the corresponding
// entry at the Vault K/V store.
func (store *KeyStore) Get(name string) (kes.Secret, error) {
	if store.client == nil {
		store.log(errNoConnection)
		return kes.Secret{}, errNoConnection
	}
	if store.sealed {
		return kes.Secret{}, kes.ErrStoreSealed
	}

	store.initialize()
	if secret, ok := store.cache.Get(name); ok {
		return secret, nil
	}

	// Since we haven't found the requested secret key in the cache
	// we reach out to Vault's K/V store and fetch it from there.
	location := fmt.Sprintf("/kv/%s/%s", store.Location, name)
	entry, err := store.client.Logical().Read(location)
	if err != nil || entry == nil {
		// Vault will not return an error if e.g. the key existed but has
		// been deleted. However, it will return (nil, nil) in this case.
		if err == nil && entry == nil {
			return kes.Secret{}, kes.ErrKeyNotFound
		}
		store.logf("vault: failed to read secret '%s': %v", location, err)
		return kes.Secret{}, err
	}

	// Verify that we got a well-formed secret key from Vault
	v, ok := entry.Data[name]
	if !ok || v == nil {
		store.logf("vault: failed to read secret '%s': entry exists but no secret key is present", location)
		return kes.Secret{}, errors.New("vault: K/V entry does not contain any value")
	}
	s, ok := v.(string)
	if !ok {
		store.logf("vault: failed to read secret '%s': invalid K/V format", location)
		return kes.Secret{}, errors.New("vault: invalid K/V entry format")
	}

	var secret kes.Secret
	if err = secret.ParseString(s); err != nil {
		store.logf("vault: failed to read secret '%s': %v", location, err)
		return secret, err
	}
	secret, _ = store.cache.Add(name, secret)
	return secret, nil
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
//
// In particular, Create creates a new K/V entry on the Vault
// key store.
func (store *KeyStore) Create(name string, secret kes.Secret) error {
	if store.client == nil {
		store.log(errNoConnection)
		return errNoConnection
	}
	if store.sealed {
		return kes.ErrStoreSealed
	}

	store.initialize()
	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
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
		return kes.ErrKeyExists
	case err != nil:
		store.logf("vault: failed to create '%s': %v", location, err)
		return err
	}

	// Finally, we create the secret key since it seems that it
	// doesn't exist. However, this is just an assumption since
	// another key server may have created that key in the meantime.
	// Since there is now way we can detect that reliable we require
	// that whoever has the permission to create keys does that in
	// a non-racy way.
	_, err := store.client.Logical().Write(location, map[string]interface{}{
		name: secret.String(),
	})
	if err != nil {
		store.logf("vault: failed to create '%s': %v", location, err)
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
		store.log(errNoConnection)
		return errNoConnection
	}
	if store.sealed {
		return kes.ErrStoreSealed
	}

	// Vault will not return an error if an entry does not
	// exist. Instead, it responds with 204 No Content and
	// no body. In this case the client also returns a nil-error
	// Therefore, we can just try to delete it in any case.
	location := fmt.Sprintf("/kv/%s/%s", store.Location, name)
	_, err := store.client.Logical().Delete(location)
	store.cache.Delete(name)
	if err != nil {
		store.logf("vault: failed to delete '%s': %v", location, err)
	}
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
	if delay == 0 {
		delay = 10 * time.Second
	}
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
	if login.Retry == 0 {
		login.Retry = 5 * time.Second
	}
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

// errNoConnection is the error returned and logged by
// the key store if the vault client hasn't been initialized.
//
// This error is returned by Create, Get, Delete, a.s.o.
// in case of an invalid configuration - i.e. when Authenticate()
// hasn't been called.
var errNoConnection = errors.New("vault: no connection to vault server")

func (store *KeyStore) initialize() {
	if atomic.CompareAndSwapUint32(&store.once, 0, 1) {
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}

func (store *KeyStore) log(v ...interface{}) {
	if store.ErrorLog == nil {
		log.Println(v...)
	} else {
		store.ErrorLog.Println(v...)
	}
}

func (store *KeyStore) logf(format string, v ...interface{}) {
	if store.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		store.ErrorLog.Printf(format, v...)
	}
}
