// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
)

// Credentials are Azure client credentials to authenticate an application
// accessing Azure service.
type Credentials struct {
	TenantID string // The ID of the Azure tenant
	ClientID string // The ID of the Azure client accessing KeyVault
	Secret   string // The secret value of the Azure client
}

// ManagedIdentity is an Azure managed identity.
//
// It allows applications running inside Azure to authenticate
// to Azure services via a managed identity object containing
// the access credentials.
type ManagedIdentity struct {
	ClientID string // The Azure managed identity client ID
}

// KeyVault is a secret store that uses Azure KeyVault for storing secrets.
type KeyVault struct {
	Endpoint string // The Azure KeyVault Endpoint

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	client client
}

var _ key.Store = (*KeyVault)(nil)

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Status returns the current state of the Azure KeyVault instance.
// In particular, whether it is reachable and the network latency.
func (kv *KeyVault) Status(ctx context.Context) (key.StoreState, error) {
	state, err := key.DialStore(ctx, kv.Endpoint)
	if err != nil {
		return key.StoreState{}, err
	}
	if state.State == key.StoreReachable {
		state.State = key.StoreAvailable
	}
	return state, nil
}

// Create creates the given key-value pair as KeyVault secret.
//
// Since KeyVault does not support an atomic create resp.
// create-only-if-not-exists, Create cannot exclude data
// race situations when multiple clients try to create
// the same secret at the same time.
//
// However, Create checks whether a secret with the given
// name exists, and if it does, returns kes.ErrKeyExists.
//
// Further, a secret may not exist but may be in a soft delete
// state. In this case, Create tries to purge the deleted
// secret and then tries to create it. However, KeyVault
// purges deleted secrets in the background such that
// an incoming create fails with HTTP 409 Conflict. Therefore,
// Create tries to create the secret multiple times after
// purging but will eventually give up and fail. However,
// a subsequent create may succeed once KeyVault has purged
// the secret completely.
func (kv *KeyVault) Create(ctx context.Context, name string, key key.Key) error {
	_, stat, err := kv.client.GetSecret(ctx, name, "")
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			kv.logf("azure: failed to create %q: failed to check whether %q already exists: %v", name, name, err)
		}
		return errCreateKey
	}
	switch {
	case stat.StatusCode == http.StatusOK:
		return kes.ErrKeyExists
	case stat.StatusCode == http.StatusForbidden && stat.ErrorCode == "ForbiddenByPolicy":
		kv.logf("azure: failed to create %q: insufficient permissions to check whether %q already exists: %s (%s)", name, name, stat.Message, stat.ErrorCode)
		return errCreateKey
	default:
		if stat.StatusCode != http.StatusNotFound {
			kv.logf("azure: failed to create %q: failed to check whether %q already exists: %s (%s)", name, name, stat.Message, stat.ErrorCode)
			return errCreateKey
		}
	}

	encodedKey, err := key.MarshalText()
	if err != nil {
		kv.logf("azure: failed to encode key '%s': %v", name, err)
		return errCreateKey
	}
	stat, err = kv.client.CreateSecret(ctx, name, string(encodedKey))
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			kv.logf("azure: failed to create %q: %v", name, err)
		}
		return errCreateKey
	}
	if stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsDeletedButRecoverable" {
		stat, err = kv.client.PurgeSecret(ctx, name)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				kv.logf("azure: failed to create %q: failed to purge deleted secret: %v", name, err)
			}
			return errCreateKey
		}
		if stat.StatusCode != http.StatusNoContent {
			kv.logf("azure: failed to create %q: failed to purge deleted secret: %s (%s)", name, stat.Message, stat.ErrorCode)
			return errCreateKey
		}

		const (
			Retry  = 7
			Delay  = 200 * time.Millisecond
			Jitter = 800 * time.Millisecond
		)
		for i := 0; i < Retry; i++ {
			stat, err = kv.client.CreateSecret(ctx, name, string(encodedKey))
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					kv.logf("azure: failed to create %q: %v", name, err)
				}
				return errDeleteKey
			}
			if stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsBeingDeleted" {
				time.Sleep(Delay + time.Duration(rand.Int63n(Jitter.Milliseconds()))*time.Millisecond)
				continue
			}
			break
		}
	}
	switch {
	case stat.StatusCode == http.StatusOK:
		return nil
	case stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsDeletedButRecoverable":
		kv.logf("azure: failed to create %q: key already exists but is currently marked as deleted. Either restore or purge %q", name, name)
	case stat.StatusCode == http.StatusForbidden && stat.ErrorCode == "ForbiddenByPolicy":
		kv.logf("azure: failed to create %q: insufficient permissions: %s", name, stat.Message)
	default:
		kv.logf("azure: failed to create %q: %s (%s)", name, stat.Message, stat.ErrorCode)
	}
	return errCreateKey
}

// Delete deletes and purges the secret from KeyVault.
//
// A full delete is a two-step process. So, Delete first
// tries to delete and then purge the (soft) deleted secret.
// However, KeyVault may return success even though it hasn't
// completed the (soft) deletion process. A subsequent purge
// operation may tmp. fail with HTTP 409 conflict.
//
// Therefore, Delete retries to purge a deleted secret multiple
// times. However, it will not return an error when all attempts
// fail with HTTP 409 since KeyVault will eventually catch up
// and purge the secret. Further, a subsequent Create operation
// will also try to purge the secret.
//
// Since KeyVault only supports two-steps deletes, KES cannot
// guarantee that a Delete operation has atomic semantics.
func (kv *KeyVault) Delete(ctx context.Context, name string) error {
	// Deleting a key from KeyVault is a two-step
	// process. First, the key has to be deleted
	// (soft delete) and then purged. It is not
	// possible to purge a secret directly.
	//
	// Further, a soft delete takes some time.
	// KeyVault may return 200 OK indicating a
	// successful soft-delete. However, the key
	// may not be ready to be purged. Instead,
	// the key deletion may still be in progress.
	// Trying to purge a key that has not been
	// deleted causes KeyVault to return 409
	// Conflict and the KeyVault error code
	// "ObjectIsBeingDeleted".
	// In this case, we have to retry purging the
	// key - hoping that KeyVault finishes the
	// internal soft-delete process.

	stat, err := kv.client.DeleteSecret(ctx, name)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			kv.logf("azure: failed to delete %q: %v", name, err)
		}
		return errDeleteKey
	}
	if stat.StatusCode != http.StatusOK && stat.StatusCode != http.StatusNotFound {
		kv.logf("azure: failed to delete %q: %s (%s)", name, stat.Message, stat.ErrorCode)
		return errDeleteKey
	}

	// Now, the key either does not exist, is being deleted or
	// has been deleted. If the key does not exist then purging
	// it will result in a 404 NotFound.
	// If the key has been marked as deleted then purging it
	// should succeed with 204 NoContent.
	// However, if the key is not ready to be purged then we
	// retry purging the key a couple of times - hoping that
	// KeyVault completes the soft-delete process.
	const (
		Retry  = 7
		Delay  = 200 * time.Millisecond
		Jitter = 800 * time.Millisecond
	)
	for i := 0; i < Retry; i++ {
		stat, err = kv.client.PurgeSecret(ctx, name)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				kv.logf("azure: failed to delete %q: %s (%s)", name, stat.Message, stat.ErrorCode)
			}
			return errDeleteKey
		}
		switch {
		case stat.StatusCode == http.StatusNoContent:
			return nil
		case stat.StatusCode == http.StatusNotFound:
			return nil
		case stat.StatusCode == http.StatusForbidden && stat.ErrorCode == "ForbiddenByPolicy":
			return nil
		case stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsBeingDeleted":
			time.Sleep(Delay + time.Duration(rand.Int63n(Jitter.Milliseconds()))*time.Millisecond)
			continue
		default:
			break
		}
	}
	if stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsBeingDeleted" {
		return nil
	}
	kv.logf("azure: failed to delete %q: failed to purge deleted secret: %s (%s)", name, stat.Message, stat.ErrorCode)
	return errDeleteKey
}

// Get returns the first resp. oldest version of the secret.
// It returns kes.ErrKeyNotFound if no such secret exists.
//
// Since Get has to fetch and filter the secrets versions first
// before actually accessing the secret, Get may return inconsistent
// responses when the secret is modified concurrently.
func (kv *KeyVault) Get(ctx context.Context, name string) (key.Key, error) {
	version, stat, err := kv.client.GetFirstVersion(ctx, name)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			kv.logf("azure: failed to get %q: failed to list versions: %v", name, err)
		}
		return key.Key{}, err
	}
	if stat.StatusCode == http.StatusNotFound && stat.ErrorCode == "NoObjectVersions" {
		return key.Key{}, kes.ErrKeyNotFound
	}
	if stat.StatusCode != http.StatusOK {
		kv.logf("azure: failed to get %q: failed to list versions: %s (%s)", name, stat.Message, stat.ErrorCode)
		return key.Key{}, errGetKey
	}

	value, stat, err := kv.client.GetSecret(ctx, name, version)
	if err != nil {
		kv.logf("azure: failed to get %q: %v", name, err)
		return key.Key{}, errGetKey
	}
	if stat.StatusCode != http.StatusOK {
		kv.logf("azure: failed to get %q: %s (%s)", name, stat.Message, stat.ErrorCode)
		return key.Key{}, errGetKey
	}
	k, err := key.Parse([]byte(value))
	if err != nil {
		kv.logf("azure: failed to parse key %q: %v", name, err)
		return key.Key{}, err
	}
	return k, nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (kv *KeyVault) List(ctx context.Context) (key.Iterator, error) {
	var (
		values   = make(chan string, 10)
		iterator = &iterator{
			values: values,
		}
	)
	go func() {
		defer close(values)

		var nextLink string
		for {
			secrets, link, status, err := kv.client.ListSecrets(ctx, nextLink)
			if errors.Is(err, context.Canceled) {
				break
			}
			if err != nil {
				kv.logf("azure: failed to list keys: %v", err)
				iterator.SetErr(errListKey)
				break
			}
			if status.StatusCode != http.StatusOK {
				kv.logf("azure: failed to list keys: %s (%s)", status.Message, status.ErrorCode)
				iterator.SetErr(errListKey)
				break
			}
			nextLink = link
			for _, secret := range secrets {
				values <- secret
			}
			if nextLink == "" {
				break
			}
		}
	}()
	return iterator, nil
}

// AuthenticateWithCredentials tries to establish a connection to a Azure KeyVault
// instance using Azure client credentials.
//
// It retruns an error if no connection could be
// established - for instance because of invalid
// credentials.
func (kv *KeyVault) AuthenticateWithCredentials(creds Credentials) error {
	const Scope = "https://vault.azure.net"

	c := auth.NewClientCredentialsConfig(creds.ClientID, creds.Secret, creds.TenantID)
	c.Resource = Scope
	token, err := c.ServicePrincipalToken()
	if err != nil {
		return fmt.Errorf("azure: failed to obtain ServicePrincipalToken from client credentials: %v", err)
	}
	kv.client = client{
		Endpoint:   kv.Endpoint,
		Authorizer: autorest.NewBearerAuthorizer(token),
	}
	return nil
}

// AuthenticateWithIdentity tries to establish a connection to a Azure KeyVault
// instance using an Azure managed identity.
//
// It retruns an error if no connection could be
// established - for instance because of invalid
// credentials.
func (kv *KeyVault) AuthenticateWithIdentity(msi ManagedIdentity) error {
	const Scope = "https://vault.azure.net"

	c := auth.NewMSIConfig()
	c.Resource = Scope
	c.ClientID = msi.ClientID
	token, err := c.ServicePrincipalToken()
	if err != nil {
		return fmt.Errorf("azure: failed to obtain ServicePrincipalToken from managed identity: %v", err)
	}
	kv.client = client{
		Endpoint:   kv.Endpoint,
		Authorizer: autorest.NewBearerAuthorizer(token),
	}
	return nil
}

type iterator struct {
	values <-chan string
	last   string

	lock sync.Mutex
	err  error
}

func (i *iterator) Next() bool {
	v, ok := <-i.values
	if !ok {
		return false
	}
	i.last = v
	return true
}

func (i *iterator) Name() string { return i.last }

func (i *iterator) Err() error {
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.err
}

func (i *iterator) SetErr(err error) {
	i.lock.Lock()
	i.err = err
	i.lock.Unlock()
}

func (kv *KeyVault) logf(format string, v ...interface{}) {
	if kv.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		kv.ErrorLog.Printf(format, v...)
	}
}
