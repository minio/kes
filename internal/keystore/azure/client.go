// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// status represents a KeyVault operation results.
// It contains the HTTP response code returned by
// KeyVault - and, in case of an error, a KeyVault
// error code, if available, and an error message.
type status struct {
	StatusCode int // The HTTP response status code

	ErrorCode string // The KeyVault error code
	Message   string // The KeyVault error message
}

type client struct {
	azsecretsClient *azsecrets.Client
}

// CreateSecret creates a KeyVault secret with
// the given name and the given value.
//
// It returns a status with an HTTP 200 OK
// status code on success.
//
// If a secret with the given name does not exist
// then KeyVault will not return an error but create
// another version of the secret with the given value.
func (c *client) CreateSecret(ctx context.Context, name, value string) (status, error) {
	_, err := c.azsecretsClient.SetSecret(ctx, name, azsecrets.SetSecretParameters{
		Value: &value,
	}, nil)
	if err != nil {
		return transportErrToStatus(err)
	}
	return status{
		StatusCode: http.StatusOK,
	}, nil
}

// GetSecret returns the version of the secret with
// the given name. If version is empty then KeyVault
// will return the latest version of the secret.
//
// A KeyVault secret may have additional attributes:
//
//	{
//	   Enabled
//	   Expiry
//	   NotBefore
//	   ...
//	}
//
// GetSecret returns no secret and an error status
// if the secret is disabled, expired or should not
// be used, yet.
func (c *client) GetSecret(ctx context.Context, name, version string) (string, status, error) {
	response, err := c.azsecretsClient.GetSecret(ctx, name, version, nil)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "", status{}, err
	}
	if err != nil {
		stat, err := transportErrToStatus(err)
		return "", stat, err
	}
	if response.Attributes.Enabled != nil && !*response.Attributes.Enabled {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectIsDisabled",
			Message:    fmt.Sprintf("The secret %q is disabled and cannot be used", name),
		}, nil
	}
	if response.Attributes.NotBefore != nil && time.Since(*response.Attributes.NotBefore) <= 0 {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectMustNotBeUsed",
			Message:    fmt.Sprintf("The secret %q must not be used before %v", name, *response.Attributes.NotBefore),
		}, nil
	}
	if response.Attributes.Expires != nil && time.Until(*response.Attributes.Expires) <= 0 {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectIsExpired",
			Message:    fmt.Sprintf("The secret %q is expired and cannot be used", name),
		}, nil
	}

	if response.Value != nil {
		return *response.Value, status{
			StatusCode: http.StatusOK,
		}, nil
	}
	return "", status{
		StatusCode: http.StatusOK,
	}, nil
}

// DeleteSecret issues a (soft) delete of the secret with the
// given name. It does not purge an already deleted secret.
//
// A deleted secret can either be recovered with a certain time
// window - i.e. 7 days up to >= 90 days - or be purged using
// a dedicated purge API.
//
// KeyVault does not guarantee that the secret has been deleted
// even if it returns 200 OK. Instead, the secret may be in
// a transition state from "active" to (soft) deleted.
func (c *client) DeleteSecret(ctx context.Context, name string) (status, error) {
	_, err := c.azsecretsClient.DeleteSecret(ctx, name, nil)
	if err != nil {
		return transportErrToStatus(err)
	}
	return status{
		StatusCode: http.StatusOK,
	}, nil
}

// PurgeSecret purges the (soft) deleted secret with the given
// name. It cannot be used to delete an "active" secret. Instead,
// it removes a deleted secret permanently such that it cannot be
// recovered. Therefore, deleting a KeyVault secret permanently is
// a two-step process.
func (c *client) PurgeSecret(ctx context.Context, name string) (status, error) {
	_, err := c.azsecretsClient.PurgeDeletedSecret(ctx, name, nil)
	if err != nil {
		stat, err := transportErrToStatus(err)
		if stat.StatusCode != http.StatusNoContent && stat.StatusCode != http.StatusOK && stat.StatusCode != http.StatusNotFound {
			return stat, err
		}
	}
	return status{
		StatusCode: http.StatusOK,
	}, nil
}

// GetFirstVersion returns the first version of a secret
// based on its created_at timestamp.
//
// To reduce complexity, GetFirstVersion makes some simplifying
// assumptions. In particular, it only inspects 25 (KeyVault API default)
// versions of the given secret. When a secret contains more then 25
// versions GetFirstVersions returns a status with a 422 HTTP error code.
func (c *client) GetFirstVersion(ctx context.Context, name string) (string, status, error) {
	pager := c.azsecretsClient.NewListSecretPropertiesVersionsPager(name, nil)
	page, err := pager.NextPage(ctx)
	if err != nil {
		stat, err := transportErrToStatus(err)
		return "", stat, err
	}
	if pager.More() {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "TooManyObjectVersions",
			Message:    fmt.Sprintf("There are too many versions of %q.", name),
		}, nil
	}
	if len(page.SecretPropertiesListResult.Value) == 0 {
		return "", status{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "NoObjectVersions",
			Message:    fmt.Sprintf("There are no versions of %q.", name),
		}, nil
	}
	var (
		version   string           // most recent Secret version
		createdAt *time.Time = nil // most recent createdAt UNIX timestamp
	)
	for _, v := range page.SecretPropertiesListResult.Value {
		if v.Attributes != nil && v.Attributes.Created != nil && v.ID != nil {
			if createdAt == nil || createdAt.After(*v.Attributes.Created) {
				createdAt = v.Attributes.Created
				version = v.ID.Version()
			}
		}
	}
	return version, status{
		StatusCode: http.StatusOK,
	}, nil
}
