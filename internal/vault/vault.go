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
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
)

// KeyStore is a Hashicorp Vault K/V client.
//
// It creates, deletes, stores and fetches key
// value pairs using the Hashicorp Vault K/V
// secret engine.
type KeyStore struct {
	client *client
	config *Config
}

// Connect connects and authenticates to a Hashicorp
// Vault server.
func Connect(ctx context.Context, c *Config) (*KeyStore, error) {
	c = c.Clone()
	if c == nil {
		c = &Config{}
	}
	c.setDefaults()

	if c.APIVersion != APIv1 && c.APIVersion != APIv2 {
		return nil, fmt.Errorf("vault: invalid engine API version %q", c.APIVersion)
	}

	var tlsConfig = &vaultapi.TLSConfig{
		ClientKey:  c.ClientKeyPath,
		ClientCert: c.ClientCertPath,
	}
	if c.CAPath != "" {
		stat, err := os.Stat(c.CAPath)
		if err != nil {
			return nil, fmt.Errorf("vault: failed to open %q: %v", c.CAPath, err)
		}
		if stat.IsDir() {
			tlsConfig.CAPath = c.CAPath
		} else {
			tlsConfig.CACert = c.CAPath
		}
	}

	var config = vaultapi.DefaultConfig()
	config.Address = c.Endpoint
	config.ConfigureTLS(tlsConfig)
	vaultClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	var client = &client{
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
		if c.K8S.Role != "" || c.K8S.JWT != "" {
			return nil, errors.New("vault: ambigious authentication: AppRole and K8S credentials specified at the same time")
		}
		authenticate = client.AuthenticateWithAppRole(c.AppRole)
	case c.K8S.Role != "" || c.K8S.JWT != "":
		if c.AppRole.ID != "" || c.AppRole.Secret != "" {
			return nil, errors.New("vault: ambigious authentication: AppRole and K8S credentials specified at the same time")
		}
		authenticate = client.AuthenticateWithK8S(c.K8S)
	default:
		return nil, errors.New("vault: no or empty authentication credentials specified")
	}

	token, ttl, err := authenticate()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	go client.CheckStatus(ctx, c.StatusPingAfter)
	go client.RenewToken(ctx, authenticate, ttl, retry)
	return &KeyStore{
		config: c,
		client: client,
	}, nil
}

var _ key.Store = (*KeyStore)(nil)

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")

	errSealed = errors.New("vault: key store is sealed")
)

// Status returns the current state of the Hashicorp Vault instance.
// In particular, whether it is reachable and the network latency.
func (s *KeyStore) Status(ctx context.Context) (key.StoreState, error) {
	state, err := key.DialStore(ctx, s.config.Endpoint)
	if err != nil {
		return key.StoreState{}, err
	}
	if state.State == key.StoreUnreachable {
		return state, nil
	}

	// Vault is reachable over the network. Now, we fetch Vault health
	// information to check whether it can serve requests.
	// We use a custom version of the Client.Sys().Health() SDK function
	// since we cannot pass our context.

	var req = s.client.NewRequest(http.MethodGet, "/v1/sys/health")
	// If the code is 400 or above it will automatically turn into an error,
	// but the sys/health API defaults to returning 5xx when not sealed or
	// initialized, so we force this code to be something else so we parse correctly
	req.Params.Add("uninitcode", "299")
	req.Params.Add("sealedcode", "299")
	req.Params.Add("standbycode", "299")
	req.Params.Add("drsecondarycode", "299")
	req.Params.Add("performancestandbycode", "299")

	resp, err := s.client.RawRequestWithContext(ctx, req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return state, nil
	}
	if err != nil {
		s.logf("vault: failed to fetch health status information: %v", err)
		return state, nil
	}
	defer resp.Body.Close()

	var response vaultapi.HealthResponse
	if err = resp.DecodeJSON(&response); err != nil {
		s.logf("vault: failed to fetch health status information: %v", err)
		return state, nil
	}
	if response.Initialized && !response.Sealed {
		state.State = key.StoreAvailable
	}
	return state, nil

}

// Create creates the given key-value pair at Vault if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *KeyStore) Create(ctx context.Context, name string, key key.Key) error {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.config.Endpoint)
		return errCreateKey
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
			s.logf("vault: entry exist but failed to read %q: invalid K/V v1 format", location)
			return errors.New("vault: invalid K/V v1 format")
		}
		return kes.ErrKeyExists
	case err == nil && secret != nil && s.config.APIVersion == APIv2 && len(secret.Data) > 0:
		var data = secret.Data
		v, ok := data["data"]
		if !ok || v == nil {
			s.logf("vault: entry exists but failed to read %q: invalid K/V v2 format: missing 'data' entry", location)
			return errCreateKey
		}
		data, ok = v.(map[string]interface{})
		if !ok || data == nil {
			s.logf("vault: entry exists but failed to read %q: invalid K/V v2 format: invalid 'data' entry", location)
			return errCreateKey
		}
		if _, ok := data[name]; !ok {
			s.logf("vault: failed to read %q: entry exists but no secret key is present", location)
			return errCreateKey
		}
		return kes.ErrKeyExists
	case err != nil:
		s.logf("vault: failed to create %q: %v", location, err)
		return err
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
				name: key.String(),
			},
		}
	} else {
		data = map[string]interface{}{
			name: key.String(),
		}
	}

	// The Vault SDK may not return an error even if it hasn't created
	// an entry - e.g. in case of some network errors. Therefore, we
	// implement the specific key creation logic ourself.
	//
	// We expect HTTP 204 (No Content) when a key got created successfully.
	// So, we check that Vault response with 204. Otherwise, we return an
	// error.
	var req = s.client.Client.NewRequest(http.MethodPut, "/v1/"+location)
	if err := req.SetJSONBody(data); err != nil {
		s.logf("vault: failed to create %q: %v", location, err)
		return err
	}
	resp, err := s.client.Client.RawRequestWithContext(ctx, req)
	if err != nil {
		s.logf("vault: failed to create %q: %v", location, err)
		return err
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != http.StatusNoContent {
		if _, err = vaultapi.ParseSecret(resp.Body); err != nil {
			s.logf("vault: failed to create %q: %v", location, err)
			return err
		}
		err = fmt.Errorf("expected response %s (%d) but received %s (%d)", resp.Status, resp.StatusCode, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		s.logf("vault: failed to create %q: %v", location, err)
		return err
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *KeyStore) Get(_ context.Context, name string) (key.Key, error) {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.config.Endpoint)
		return key.Key{}, errGetKey
	}
	if s.client.Sealed() {
		return key.Key{}, errSealed
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
			return key.Key{}, kes.ErrKeyNotFound
		}
		s.logf("vault: failed to read %q: %v", location, err)
		return key.Key{}, errGetKey
	}

	var data = entry.Data
	if s.config.APIVersion == APIv2 { // See: https://www.vaultproject.io/api/secret/kv/kv-v2#sample-response-1 (differs from v1 format)
		v, ok := entry.Data["data"]
		if !ok || v == nil {
			s.logf("vault: failed to read %q: invalid K/V v2 format: missing 'data' entry", location)
			return key.Key{}, errGetKey
		}
		data, ok = v.(map[string]interface{})
		if !ok || data == nil {
			s.logf("vault: failed to read %q: invalid K/V v2 format: invalid 'data' entry", location)
			return key.Key{}, errGetKey
		}
	}

	// Verify that we got a well-formed response from Vault
	v, ok := data[name]
	if !ok || v == nil {
		s.logf("vault: failed to read %q: entry exists but no secret key is present", location)
		return key.Key{}, errGetKey
	}
	value, ok := v.(string)
	if !ok {
		s.logf("vault: failed to read %q: invalid K/V format", location)
		return key.Key{}, errGetKey
	}
	k, err := key.Parse(value)
	if err != nil {
		s.logf("vault: failed to parse key at %q: %v", location, err)
		return key.Key{}, err
	}
	return k, nil
}

// Delete removes a the value associated with the given key
// from Vault, if it exists.
func (s *KeyStore) Delete(ctx context.Context, name string) error {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.config.Endpoint)
		return errDeleteKey
	}
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
	var req = s.client.Client.NewRequest(http.MethodDelete, "/v1/"+location)
	resp, err := s.client.Client.RawRequestWithContext(ctx, req)
	if err != nil {
		s.logf("vault: failed to delete %q: %v", location, err)
		return err
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if resp.StatusCode != http.StatusNoContent {
		if _, err := vaultapi.ParseSecret(resp.Body); err != nil {
			s.logf("vault: failed to delete %q: %v", location, err)
			return err
		}
		err = fmt.Errorf("expected response %s (%d) but received %s (%d)", resp.Status, resp.StatusCode, http.StatusText(http.StatusNoContent), http.StatusNoContent)
		s.logf("vault: failed to delete %q: %v", location, err)
		return err
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *KeyStore) List(ctx context.Context) (key.Iterator, error) {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.config.Endpoint)
		return nil, errListKey
	}
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
		s.logf("vault: failed to list %q: %v", location, err)
		return nil, err
	}
	defer resp.Body.Close()

	// Vault returns all keys in one request and does not provide a
	// (reasonable) way to parse the response in batches or use some
	// form of pagination. Therefore, we limit the response body to
	// a some reasonable limit to not exceed memory resources.
	const MaxBody = 32 * 1 << 20
	secret, err := vaultapi.ParseSecret(io.LimitReader(resp.Body, MaxBody))
	if err != nil {
		s.logf("vault: failed to list %q: %v", location, err)
		return nil, err
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
		s.logf("vault: failed to list '%s': invalid key listing format", location)
		return nil, errListKey
	}
	return &iterator{
		values: values,
	}, nil
}

func (s *KeyStore) logf(format string, v ...interface{}) {
	if s.config.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.config.ErrorLog.Printf(format, v...)
	}
}
