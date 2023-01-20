// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package vault implements a secret key store that
// stores secret keys as key-value entries on the
// Hashicorp Vault K/V secret backend.
//
// Vault is a KMS implementation with many features.
// This packages only leverages the key-value store.
// For an introduction to Vault see: https://www.vaultproject.io/
// For an K/V API overview see: https://www.vaultproject.io/api/secret/kv/kv-v1.html
package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"aead.dev/mem"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
	"github.com/minio/kes/kms"
)

// Conn is a connection to a Hashicorp Vault server.
type Conn struct {
	client *client
	config *Config
}

// Connect connects to a Hashicorp Vault server with
// the given configuration.
func Connect(ctx context.Context, c *Config) (*Conn, error) {
	c = c.Clone()

	if c.Engine == "" {
		c.Engine = EngineKV
	}
	if c.APIVersion == "" {
		c.APIVersion = APIv1
	}
	if c.AppRole.Retry == 0 {
		c.AppRole.Retry = 5 * time.Second
	}
	if c.AppRole.Engine == "" {
		c.AppRole.Engine = EngineAppRole
	}
	if c.K8S.Engine == "" {
		c.K8S.Engine = EngineKubernetes
	}
	if c.K8S.Retry == 0 {
		c.K8S.Retry = 5 * time.Second
	}
	if c.StatusPingAfter == 0 {
		c.StatusPingAfter = 15 * time.Second
	}

	if c.Endpoint == "" {
		return nil, fmt.Errorf("vault: endpoint is empty")
	}
	if c.APIVersion != APIv1 && c.APIVersion != APIv2 {
		return nil, fmt.Errorf("vault: invalid engine API version '%s'", c.APIVersion)
	}
	if (c.AppRole.ID == "" || c.AppRole.Secret == "") && (c.K8S.JWT == "" || c.K8S.Role == "") {
		return nil, errors.New("vault: no authentication method specified")
	}
	if (c.AppRole.ID != "" || c.AppRole.Secret != "") && (c.K8S.JWT != "" || c.K8S.Role != "") {
		return nil, errors.New("vault: ambigious authentication: approle and kubernetes method specified")
	}

	tlsConfig := &vaultapi.TLSConfig{
		ClientKey:  c.PrivateKey,
		ClientCert: c.Certificate,
	}
	if c.CAPath != "" {
		stat, err := os.Stat(c.CAPath)
		if err != nil {
			return nil, fmt.Errorf("vault: failed to open '%s': %v", c.CAPath, err)
		}
		if stat.IsDir() {
			tlsConfig.CAPath = c.CAPath
		} else {
			tlsConfig.CACert = c.CAPath
		}
	}

	config := vaultapi.DefaultConfig()
	config.Address = c.Endpoint
	config.ConfigureTLS(tlsConfig)
	vaultClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	client := &client{
		Client: vaultClient,
	}
	if c.Namespace != "" {
		// We must only set the namespace if it is not
		// empty. If namespace == "" the vault client
		// will send an empty namespace HTTP header -
		// which is not what we want.
		client.SetNamespace(c.Namespace)
	}

	var (
		authenticate authFunc
		retry        time.Duration
	)
	switch {
	case c.AppRole.ID != "" || c.AppRole.Secret != "":
		authenticate, retry = client.AuthenticateWithAppRole(c.AppRole), c.AppRole.Retry
	case c.K8S.Role != "" || c.K8S.JWT != "":
		jwt, err := os.ReadFile(c.K8S.JWT) // The JWT may be a file path containing the actaul token
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil {
			c.K8S.JWT = string(jwt)
		}
		authenticate, retry = client.AuthenticateWithK8S(c.K8S), c.K8S.Retry
	}

	token, ttl, err := authenticate()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	go client.CheckStatus(ctx, c.StatusPingAfter)
	go client.RenewToken(ctx, authenticate, ttl, retry)
	return &Conn{
		config: c,
		client: client,
	}, nil
}

var _ kms.Conn = (*Conn)(nil)

var errSealed = errors.New("vault: key store is sealed")

// Status returns the current state of the Hashicorp Vault instance.
// In particular, whether it is reachable and the network latency.
func (s *Conn) Status(ctx context.Context) (kms.State, error) {
	// This is a workaround for https://github.com/hashicorp/vault/issues/14934
	// The Vault SDK should not set the X-Vault-Namespace header
	// for root-only API paths.
	// Otherwise, Vault may respond with: 404 - unsupported path
	client, err := s.client.Clone()
	if err != nil {
		return kms.State{}, err
	}
	client.ClearNamespace()

	// First, we try to fetch the Vault health information.
	// Only if this fails we try to dial Vault directly over
	// a TCP connection. See: https://github.com/minio/kes/issues/230

	start := time.Now()
	health, err := client.Sys().HealthWithContext(ctx)
	if err == nil {
		switch {
		case !health.Initialized:
			return kms.State{}, &kms.Unavailable{Err: errors.New("vault: not initialized")}
		case health.Sealed:
			return kms.State{}, &kms.Unavailable{Err: errSealed}
		default:
			return kms.State{Latency: time.Since(start)}, nil
		}
	}
	if errors.Is(err, context.Canceled) && errors.Is(err, context.DeadlineExceeded) {
		return kms.State{}, &kms.Unreachable{Err: err}
	}
	return kms.Dial(ctx, s.config.Endpoint)
}

// Create creates the given key-value pair at Vault if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *Conn) Create(ctx context.Context, name string, value []byte) error {
	if s.client == nil {
		return errors.New("vault: no connection to " + s.config.Endpoint)
	}
	if s.client.Sealed() {
		return errSealed
	}

	// We try to check whether key exists on the K/V store.
	// If so, we must not overwrite it.
	var location string
	if s.config.APIVersion == APIv2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#create-update-secret
		location = path.Join(s.config.Engine, "data", s.config.Prefix, name) // /<engine>/data/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#create-update-secret
		location = path.Join(s.config.Engine, s.config.Prefix, name) // /<engine>/<location>/<name>
	}

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
	// and a non-nil "secret". In this case, the secret key either
	// already exists or the K/V backend does not understand the
	// request (K/V v1 vs. K/V v2) and returns a "secret" without
	// a key entry but an API warning.
	//
	// But when the client returns an error it does not mean that
	// the entry does not exist but that some other error (e.g.
	// network error) occurred.
	switch secret, err := s.client.Logical().Read(location); {
	case err == nil && secret != nil && s.config.APIVersion != APIv2:
		if _, ok := secret.Data[name]; !ok {
			return fmt.Errorf("vault: entry exist but failed to read '%s': invalid K/V v1 format", location)
		}
		return kes.ErrKeyExists
	case err == nil && secret != nil && s.config.APIVersion == APIv2 && len(secret.Data) > 0:
		data := secret.Data
		v, ok := data["data"]
		if !ok || v == nil {
			return fmt.Errorf("vault: entry exists but failed to read '%s': invalid K/V v2 format: missing 'data' entry", location)
		}
		data, ok = v.(map[string]interface{})
		if !ok || data == nil {
			return fmt.Errorf("vault: entry exists but failed to read '%s': invalid K/V v2 format: invalid 'data' entry", location)
		}
		if _, ok := data[name]; !ok {
			return fmt.Errorf("vault: failed to read '%s': entry exists but no secret key is present", location)
		}
		return kes.ErrKeyExists
	case err != nil:
		return fmt.Errorf("vault: failed to create '%s': %v", location, err)
	}

	// Finally, we create the value since it seems that it
	// doesn't exist. However, this is just an assumption since
	// another key server may have created that key in the meantime.
	// Since there is now way we can detect that reliable we require
	// that whoever has the permission to create keys does that in
	// a non-racy way.
	var data map[string]interface{}
	if s.config.APIVersion == APIv2 {
		data = map[string]interface{}{
			"options": map[string]interface{}{
				"cas": 0, // We need to set CAS to 0 to ensure atomic creates / avoid any overwrite.
			},
			"data": map[string]interface{}{
				name: string(value),
			},
		}
	} else {
		data = map[string]interface{}{
			name: string(value),
		}
	}

	// The Vault SDK may not return an error even if it hasn't created
	// an entry - e.g. in case of some network errors. Therefore, we
	// implement the specific key creation logic ourself.
	//
	// We expect HTTP 204 (No Content) when a key got created successfully.
	// So, we check that Vault response with 204. Otherwise, we return an
	// error.
	req := s.client.Client.NewRequest(http.MethodPut, "/v1/"+location)
	if err := req.SetJSONBody(data); err != nil {
		return fmt.Errorf("vault: failed to create '%s': %v", location, err)
	}
	resp, err := s.client.Client.RawRequestWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("vault: failed to create '%s': %v", location, err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	// Vault returns 204 No Content for K/V v1 and 200 OK for K/V v2.
	// We have to check both status codes. Ref: https://github.com/minio/kes/issues/224
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		if _, err = vaultapi.ParseSecret(resp.Body); err != nil {
			return fmt.Errorf("vault: failed to create '%s': %v", location, err)
		}
		return fmt.Errorf("vault: failed to read '%s': server responded with: %s (%d)", location, resp.Status, resp.StatusCode)
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Conn) Get(_ context.Context, name string) ([]byte, error) {
	if s.client.Sealed() {
		return nil, errSealed
	}

	var location string
	if s.config.APIVersion == APIv2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#read-secret-version
		location = path.Join(s.config.Engine, "data", s.config.Prefix, name) // /<engine>/data/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#read-secret
		location = path.Join(s.config.Engine, s.config.Prefix, name) // /<engine>/<location>/<name>
	}
	entry, err := s.client.Logical().Read(location)
	if err != nil || entry == nil {
		// Vault will not return an error if e.g. the key existed but has
		// been deleted. However, it will return (nil, nil) in this case.
		if err == nil && entry == nil {
			return nil, kes.ErrKeyNotFound
		}
		return nil, fmt.Errorf("vault: failed to read '%s': %v", location, err)
	}

	data := entry.Data
	if s.config.APIVersion == APIv2 { // See: https://www.vaultproject.io/api/secret/kv/kv-v2#sample-response-1 (differs from v1 format)
		v, ok := entry.Data["data"]
		if !ok || v == nil {
			return nil, fmt.Errorf("vault: failed to read '%s': invalid K/V v2 format: missing 'data' entry", location)
		}
		data, ok = v.(map[string]interface{})
		if !ok || data == nil {
			return nil, fmt.Errorf("vault: failed to read '%s': invalid K/V v2 format: invalid 'data' entry", location)
		}
	}

	// Verify that we got a well-formed response from Vault
	v, ok := data[name]
	if !ok || v == nil {
		return nil, fmt.Errorf("vault: failed to read '%s': entry exists but no secret key is present", location)
	}
	value, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("vault: failed to read '%s': invalid K/V format", location)
	}
	return []byte(value), nil
}

// Delete removes a the value associated with the given key
// from Vault, if it exists.
func (s *Conn) Delete(ctx context.Context, name string) error {
	if s.client.Sealed() {
		return errSealed
	}

	var location string
	if s.config.APIVersion == APIv2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#delete-metadata-and-all-versions
		location = path.Join(s.config.Engine, "metadata", s.config.Prefix, name) // /<engine>/metadata/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#delete-secret
		location = path.Join(s.config.Engine, s.config.Prefix, name) // /<engine>/<location>/<name>
	}

	// The Vault SDK may not return an error even if it hasn't deleted
	// an entry - e.g. in case of some network errors. Therefore, we
	// implement the specific key deletion logic ourself.
	//
	// We expect HTTP 204 (No Content) when a key got deleted successfully.
	// So, we check that Vault response with 204. Otherwise, we return an
	// error.
	req := s.client.Client.NewRequest(http.MethodDelete, "/v1/"+location)
	resp, err := s.client.Client.RawRequestWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("vault: failed to delete '%s': %v", location, err)
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != http.StatusNoContent {
		if _, err := vaultapi.ParseSecret(resp.Body); err != nil {
			return fmt.Errorf("vault: failed to delete '%s': %v", location, err)
		}
		return fmt.Errorf("vault: failed to delete '%s': expected response %s (%d) but received %s (%d)", location, resp.Status, resp.StatusCode, http.StatusText(http.StatusNoContent), http.StatusNoContent)
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *Conn) List(ctx context.Context) (kms.Iter, error) {
	if s.client.Sealed() {
		return nil, errSealed
	}

	// We don't use the Vault SDK vault.Logical.List(string) API
	// here since the SDK does not allow us to specify a context.
	// However, if the client closes the connection (or a timeout
	// occurs, etc.) we want to abort the listing immediately.
	// Therefore, we have to use low-level SDK functionality here.

	var location string
	if s.config.APIVersion == APIv2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#list-secrets
		location = path.Join(s.config.Engine, "metadata", s.config.Prefix)
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets
		location = path.Join(s.config.Engine, s.config.Prefix)
	}

	r := s.client.NewRequest("LIST", "/v1/"+location)
	r.Params.Set("list", "true")

	resp, err := s.client.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("vault: failed to list '%s': %v", location, err)
	}
	defer resp.Body.Close()

	// Vault returns all keys in one request and does not provide a
	// (reasonable) way to parse the response in batches or use some
	// form of pagination. Therefore, we limit the response body to
	// a some reasonable limit to not exceed memory resources.
	const MaxBody = 32 * mem.MiB
	secret, err := vaultapi.ParseSecret(mem.LimitReader(resp.Body, MaxBody))
	if err != nil {
		return nil, fmt.Errorf("vault: failed to list '%s': %v", location, err)
	}
	if secret == nil { // The secret may be nil even when there was no error.
		return &iterator{}, nil // We return an empty iterator in this case.
	}

	// Vault returns a generic map that should contain
	// an array containing all key names. This array
	// however is again a generic []interface{} instead
	// of a dedicated type or []string.
	values, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("vault: failed to list '%s': invalid key listing format", location)
	}
	return kms.FuseIter(&iterator{
		values: values,
	}), nil
}
