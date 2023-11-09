// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/minio/kes"
	kesdk "github.com/minio/kes-go"
	"github.com/minio/kes/internal/keystore"
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

// Store is an Azure KeyVault secret store.
type Store struct {
	endpoint string
	client   client
}

func (s *Store) String() string { return "Azure KeyVault: " + s.endpoint }

// Status returns the current state of the Azure KeyVault instance.
// In particular, whether it is reachable and the network latency.
func (s *Store) Status(ctx context.Context) (kes.KeyStoreState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.client.Endpoint, nil)
	if err != nil {
		return kes.KeyStoreState{}, err
	}

	start := time.Now()
	if _, err = http.DefaultClient.Do(req); err != nil {
		return kes.KeyStoreState{}, &keystore.ErrUnreachable{Err: err}
	}
	return kes.KeyStoreState{
		Latency: time.Since(start),
	}, nil
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
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	_, stat, err := s.client.GetSecret(ctx, name, "")
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("azure: failed to create '%s': failed to check whether '%s' already exists: %v", name, name, err)
	}
	switch {
	case stat.StatusCode == http.StatusOK:
		return kesdk.ErrKeyExists
	case stat.StatusCode == http.StatusForbidden && stat.ErrorCode == "ForbiddenByPolicy":
		return fmt.Errorf("azure: failed to create '%s': insufficient permissions to check whether '%s' already exists: %s (%s)", name, name, stat.Message, stat.ErrorCode)
	case stat.StatusCode != http.StatusNotFound:
		return fmt.Errorf("azure: failed to create '%s': failed to check whether '%s' already exists: %s (%s)", name, name, stat.Message, stat.ErrorCode)
	}

	stat, err = s.client.CreateSecret(ctx, name, string(value))
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("azure: failed to create '%s': %v", name, err)
	}
	if stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsDeletedButRecoverable" {
		stat, err = s.client.PurgeSecret(ctx, name)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err != nil {
			return fmt.Errorf("azure: failed to create '%s': failed to purge deleted secret: %v", name, err)
		}
		if stat.StatusCode != http.StatusNoContent {
			return fmt.Errorf("azure: failed to create '%s': failed to purge deleted secret: %s (%s)", name, stat.Message, stat.ErrorCode)
		}

		const (
			Retry  = 7
			Delay  = 200 * time.Millisecond
			Jitter = 800 * time.Millisecond
		)
		for i := 0; i < Retry; i++ {
			stat, err = s.client.CreateSecret(ctx, name, string(value))
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if err != nil {
				return fmt.Errorf("azure: failed to create '%s': %v", name, err)
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
		return fmt.Errorf("azure: failed to create '%s': key already exists but is currently marked as deleted. Either restore or purge '%s'", name, name)
	case stat.StatusCode == http.StatusForbidden && stat.ErrorCode == "ForbiddenByPolicy":
		return fmt.Errorf("azure: failed to create '%s': insufficient permissions: %s", name, stat.Message)
	default:
		return fmt.Errorf("azure: failed to create '%s': %s (%s)", name, stat.Message, stat.ErrorCode)
	}
}

// Set creates the given key-value pair as KeyVault secret.
//
// Since KeyVault does not support an atomic create resp.
// create-only-if-not-exists, Set cannot exclude data
// race situations when multiple clients try to create
// the same secret at the same time.
//
// However, Set checks whether a secret with the given
// name exists, and if it does, returns kes.ErrKeyExists.
//
// Further, a secret may not exist but may be in a soft delete
// state. In this case, Set tries to purge the deleted
// secret and then tries to create it. However, KeyVault
// purges deleted secrets in the background such that
// an incoming create fails with HTTP 409 Conflict. Therefore,
// Set tries to create the secret multiple times after
// purging but will eventually give up and fail. However,
// a subsequent create may succeed once KeyVault has purged
// the secret completely.
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
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
func (s *Store) Delete(ctx context.Context, name string) error {
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

	stat, err := s.client.DeleteSecret(ctx, name)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("azure: failed to delete '%s': %v", name, err)
	}
	if stat.StatusCode != http.StatusNotFound {
		return kesdk.ErrKeyNotFound
	}
	if stat.StatusCode != http.StatusOK && stat.StatusCode != http.StatusNotFound {
		return fmt.Errorf("azure: failed to delete '%s': %s (%s)", name, stat.Message, stat.ErrorCode)
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
		stat, err = s.client.PurgeSecret(ctx, name)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if err != nil {
			return fmt.Errorf("azure: failed to delete '%s': %s (%s)", name, stat.Message, stat.ErrorCode)
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
		}
		break
	}
	if stat.StatusCode == http.StatusConflict && stat.ErrorCode == "ObjectIsBeingDeleted" {
		return nil
	}
	return fmt.Errorf("azure: failed to delete '%s': failed to purge deleted secret: %s (%s)", name, stat.Message, stat.ErrorCode)
}

// Get returns the first resp. oldest version of the secret.
// It returns kes.ErrKeyNotFound if no such secret exists.
//
// Since Get has to fetch and filter the secrets versions first
// before actually accessing the secret, Get may return inconsistent
// responses when the secret is modified concurrently.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	version, stat, err := s.client.GetFirstVersion(ctx, name)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("azure: failed to get '%s': failed to list versions: %v", name, err)
	}
	if stat.StatusCode == http.StatusNotFound && stat.ErrorCode == "NoObjectVersions" {
		return nil, kesdk.ErrKeyNotFound
	}
	if stat.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure: failed to get '%s': failed to list versions: %s (%s)", name, stat.Message, stat.ErrorCode)
	}

	value, stat, err := s.client.GetSecret(ctx, name, version)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("azure: failed to get '%s': %v", name, err)
	}
	if stat.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("azure: failed to get '%s': %s (%s)", name, stat.Message, stat.ErrorCode)
	}
	return []byte(value), nil
}

// List returns a new Iterator over the names of
// all stored keys.
// List returns the first n key names, that start with the given
// prefix, and the next prefix from which the listing should
// continue.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty
func (s *Store) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	var (
		names    []string
		nextLink string
	)
	for {
		secrets, link, status, err := s.client.ListSecrets(ctx, nextLink)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, "", err
		}
		if err != nil {
			return nil, "", fmt.Errorf("azure: failed to list keys: %v", err)
		}
		if status.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("azure: failed to list keys: %s (%s)", status.Message, status.ErrorCode)
		}

		nextLink = link
		names = append(names, secrets...)
		if nextLink == "" {
			break
		}
	}
	return keystore.List(names, prefix, n)
}

// Close closes the Store.
func (s *Store) Close() error { return nil }

// ConnectWithCredentials tries to establish a connection to a Azure KeyVault
// instance using Azure client credentials.
func ConnectWithCredentials(_ context.Context, endpoint string, creds Credentials) (*Store, error) {
	const Scope = "https://vault.azure.net"

	c := auth.NewClientCredentialsConfig(creds.ClientID, creds.Secret, creds.TenantID)
	c.Resource = Scope
	token, err := c.ServicePrincipalToken()
	if err != nil {
		return nil, fmt.Errorf("azure: failed to obtain ServicePrincipalToken from client credentials: %v", err)
	}
	return &Store{
		endpoint: endpoint,
		client: client{
			Endpoint:   endpoint,
			Authorizer: autorest.NewBearerAuthorizer(token),
		},
	}, nil
}

// ConnectWithIdentity tries to establish a connection to a Azure KeyVault
// instance using an Azure managed identity.
func ConnectWithIdentity(_ context.Context, endpoint string, msi ManagedIdentity) (*Store, error) {
	const Scope = "https://vault.azure.net"

	c := auth.NewMSIConfig()
	c.Resource = Scope
	c.ClientID = msi.ClientID
	token, err := c.ServicePrincipalToken()
	if err != nil {
		return nil, fmt.Errorf("azure: failed to obtain ServicePrincipalToken from managed identity: %v", err)
	}
	return &Store{
		endpoint: endpoint,
		client: client{
			Endpoint:   endpoint,
			Authorizer: autorest.NewBearerAuthorizer(token),
		},
	}, nil
}
