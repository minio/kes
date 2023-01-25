// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/Azure/go-autorest/autorest"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
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
	Endpoint   string
	Authorizer autorest.Authorizer
	Client     xhttp.Retry
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
	type Request struct {
		Value string `json:"value"`
	}
	body, err := json.Marshal(Request{
		Value: value,
	})
	if err != nil {
		return status{}, err
	}

	uri := endpoint(c.Endpoint, "secrets", name) + "?api-version=7.2"
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, uri, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return status{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	resp, err := c.Client.Do(req)
	if err != nil {
		return status{}, err
	}
	if resp.StatusCode == http.StatusOK {
		return status{
			StatusCode: http.StatusOK,
		}, nil
	}

	response, err := parseErrorResponse(resp)
	if err != nil {
		return status{}, err
	}
	return status{
		StatusCode: resp.StatusCode,
		ErrorCode:  response.Error.Inner.Code,
		Message:    response.Error.Message,
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
	type Response struct {
		Value string `json:"value"`
		Attr  struct {
			Enabled bool `json:"enabled"`

			Expiry    int64 `json:"exp"`
			NotBefore int64 `json:"nbf"`
			Created   int64 `json:"created"`
			Updated   int64 `json:"updated"`
		} `json:"attributes"`
	}

	uri := endpoint(c.Endpoint, "secrets", name, version) + "?api-version=7.2"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return "", status{}, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		response, err := parseErrorResponse(resp)
		if err != nil {
			return "", status{}, err
		}
		return "", status{
			StatusCode: resp.StatusCode,
			ErrorCode:  response.Error.Inner.Code,
			Message:    response.Error.Message,
		}, nil
	}

	limit := mem.Size(resp.ContentLength)
	if limit < 0 || limit > key.MaxSize {
		limit = key.MaxSize
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return "", status{}, err
	}

	// A secret may not be enabled, should not be used before a certain date or
	// should not be used after a certain date.
	if !response.Attr.Enabled {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectIsDisabled",
			Message:    fmt.Sprintf("The secret %q is current disabled and cannot be used", name),
		}, nil
	}
	if response.Attr.NotBefore > 0 && time.Since(time.Unix(response.Attr.NotBefore, 0)) <= 0 {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectMustNotBeUsed",
			Message:    fmt.Sprintf("The secret %q must not be used before %v", name, time.Unix(response.Attr.NotBefore, 0)),
		}, nil
	}
	if response.Attr.Expiry > 0 && time.Until(time.Unix(response.Attr.Expiry, 0)) <= 0 {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "ObjectIsExpired",
			Message:    fmt.Sprintf("The secret %q is expired and cannot be used", name),
		}, nil
	}
	return response.Value, status{
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
	uri := endpoint(c.Endpoint, "secrets", name) + "?api-version=7.2"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return status{}, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusOK {
			response, err := parseErrorResponse(resp)
			if err != nil {
				return status{}, err
			}
			return status{
				StatusCode: resp.StatusCode,
				ErrorCode:  response.Error.Inner.Code,
				Message:    response.Error.Message,
			}, nil
		}
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
	uri := endpoint(c.Endpoint, "deletedsecrets", name) + "?api-version=7.2"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, uri, nil)
	if err != nil {
		return status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return status{}, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return status{}, err
	}
	if resp.StatusCode != http.StatusNoContent {
		response, err := parseErrorResponse(resp)
		if err != nil {
			return status{}, err
		}
		return status{
			StatusCode: resp.StatusCode,
			ErrorCode:  response.Error.Inner.Code,
			Message:    response.Error.Message,
		}, nil
	}
	return status{
		StatusCode: http.StatusNoContent,
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
	type Response struct {
		Versions []struct {
			ID   string `json:"id"`
			Attr struct {
				Enabled bool  `json:"enabled"`
				Created int64 `json:"created"`
				Updated int64 `json:"updated"`
			} `json:"attributes"`
		} `json:"value"`

		NextLink string `json:"nextLink"`
	}
	// We only inspect 25 versions as some reasonable default limit.
	uri := endpoint(c.Endpoint, "secrets", name, "versions") + "?api-version=7.2&maxresults=25"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return "", status{}, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		response, err := parseErrorResponse(resp)
		if err != nil {
			return "", status{}, err
		}
		return "", status{
			StatusCode: resp.StatusCode,
			ErrorCode:  response.Error.Inner.Code,
			Message:    response.Error.Message,
		}, nil
	}

	const MaxSize = 10 * mem.MiB
	limit := mem.Size(resp.ContentLength)
	if limit < 0 || limit > MaxSize {
		limit = MaxSize
	}

	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return "", status{}, err
	}
	if response.NextLink != "" {
		return "", status{
			StatusCode: http.StatusUnprocessableEntity,
			ErrorCode:  "TooManyObjectVersions",
			Message:    fmt.Sprintf("There are too many versions of %q.", name),
		}, nil
	}
	if len(response.Versions) == 0 {
		return "", status{
			StatusCode: http.StatusNotFound,
			ErrorCode:  "NoObjectVersions",
			Message:    fmt.Sprintf("There are no versions of %q.", name),
		}, nil
	}
	var (
		id        string                 // most recent Secret ID
		createdAt int64  = math.MaxInt64 // most recent createdAt UNIX timestamp
	)
	for _, v := range response.Versions {
		if createdAt > v.Attr.Created {
			createdAt = v.Attr.Created
			id = v.ID
		}
	}
	return path.Base(id), status{
		StatusCode: http.StatusOK,
	}, nil
}

// ListSecrets returns a set of secrets names and an optional continuation
// link. It supports iterating over all secrets in pages. The returned
// continuation link, if not empty, can be used to obtain the next page
// of secrets.
//
// When starting a list iteration the nextLink should be empty. The returned
// continuation link is empty once there are no more pages.
func (c *client) ListSecrets(ctx context.Context, nextLink string) ([]string, string, status, error) {
	type Response struct {
		Values []struct {
			ID   string   `json:"id"`
			Attr struct{} `json:"attributes"`
		} `json:"value"`
		NextLink string `json:"nextLink"`
	}

	if nextLink == "" {
		nextLink = endpoint(c.Endpoint, "secrets") + "?maxresults=25&api-version=7.2"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextLink, nil)
	if err != nil {
		return nil, "", status{}, err
	}
	req, err = autorest.CreatePreparer(c.Authorizer.WithAuthorization()).Prepare(req)
	if err != nil {
		return nil, "", status{}, err
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, "", status{}, err
	}
	if resp.StatusCode != http.StatusOK {
		response, err := parseErrorResponse(resp)
		if err != nil {
			return nil, "", status{}, err
		}
		return nil, "", status{
			StatusCode: resp.StatusCode,
			ErrorCode:  response.Error.Inner.Code,
			Message:    response.Error.Message,
		}, nil
	}

	const MaxSize = 10 * mem.MiB
	limit := mem.Size(resp.ContentLength)
	if limit < 0 || limit > MaxSize {
		limit = MaxSize
	}
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, "", status{}, err
	}
	secrets := make([]string, 0, len(response.Values))
	for _, v := range response.Values {
		secrets = append(secrets, path.Base(v.ID))
	}
	return secrets, response.NextLink, status{
		StatusCode: http.StatusOK,
	}, nil
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   - endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   - endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
//
// Any leading or trailing whitespaces are removed from
// the endpoint before it is concatenated with the path
// elements.
//
// The path elements will not be URL-escaped.
func endpoint(endpoint string, elems ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimSuffix(endpoint, "/")

	if len(elems) > 0 && !strings.HasPrefix(elems[0], "/") {
		endpoint += "/"
	}
	return endpoint + path.Join(elems...)
}
