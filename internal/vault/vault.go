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
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
)

// AppRole holds the Vault AppRole
// authentication credentials and
// a duration after which the
// authentication should be retried
// whenever it fails.
type AppRole struct {
	Engine string // The AppRole engine path
	ID     string // The AppRole ID
	Secret string // The Approle secret ID
	Retry  time.Duration
}

type Kubernetes struct {
	Engine string // The Kubernetes auth engine path
	Role   string // The Kubernetes JWT role
	JWT    string // The Kubernetes JWT
	Retry  time.Duration
}

// Store is a key-value store that saves key-value
// pairs as entries on Vault's K/V secret backend.
type Store struct {
	// Addr is the HTTP address of the Vault server.
	Addr string

	// Engine is the path of the K/V engine to use.
	//
	// Vault allows multiple engines of the same type
	// mounted at the same time and/or engines mounted
	// at arbitrary paths.
	Engine string

	// EngineVersion is the API version of the K/V engine.
	//
	// It has to be set to "v1" for the K/V v1 engine (unversioned)
	// or to "v2" for the K/V v2 engine (versioned).
	//
	// For more information about the K/V engine differences, see:
	// https://www.vaultproject.io/docs/secrets/kv
	EngineVersion string

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

	// K8S contains the Vault Kubernetes authentication
	// credentials.
	K8S Kubernetes

	// StatusPingAfter is the duration after which
	// the KeyStore will check the status of the Vault
	// server. Particularly, this status information
	// is used to determine whether the Vault server
	// has been sealed resp. unsealed again.
	StatusPingAfter time.Duration

	// ErrorLog specifies an optional logger for errors
	// when K/V pairs cannot be stored, fetched, deleted
	// or contain invalid content.
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

	// The Vault namespace used to separate and isolate different
	// organizations / tenants at the same Vault instance. If
	// non-empty, the Vault client will send the
	//   X-Vault-Namespace: Namespace
	// HTTP header on each request. For more information see:
	// https://www.vaultproject.io/docs/enterprise/namespaces/index.html
	Namespace string

	client *client
}

var _ key.Store = (*Store)(nil)

// Authenticate tries to establish a connection to
// a Vault server using the approle credentials.
// It returns an error if no connection could be
// established - for instance because of invalid
// authentication credentials.
func (s *Store) Authenticate(context context.Context) error {
	tlsConfig := &vaultapi.TLSConfig{
		ClientKey:  s.ClientKeyPath,
		ClientCert: s.ClientCertPath,
	}
	if s.CAPath != "" {
		stat, err := os.Stat(s.CAPath)
		if err != nil {
			return fmt.Errorf("Failed to open %q: %v", s.CAPath, err)
		}
		if stat.IsDir() {
			tlsConfig.CAPath = s.CAPath
		} else {
			tlsConfig.CACert = s.CAPath
		}
	}

	config := vaultapi.DefaultConfig()
	config.Address = s.Addr
	config.ConfigureTLS(tlsConfig)
	vaultClient, err := vaultapi.NewClient(config)
	if err != nil {
		return err
	}
	s.client = &client{
		Client: vaultClient,
	}
	if s.Namespace != "" {
		// We must only set the namespace if it is not
		// empty. If namespace == "" the vault client
		// will send an empty namespace HTTP header -
		// which is not what we want.
		s.client.SetNamespace(s.Namespace)
	}

	var (
		authenticate authFunc
		retry        time.Duration
	)
	switch {
	case s.AppRole.ID != "" || s.AppRole.Secret != "":
		if s.K8S.Role != "" || s.K8S.JWT != "" {
			return errors.New("vault: ambigious authentication: AppRole and K8S credentials specified at the same time")
		}
		authenticate = s.client.AuthenticateWithAppRole(s.AppRole)
	case s.K8S.Role != "" || s.K8S.JWT != "":
		if s.AppRole.ID != "" || s.AppRole.Secret != "" {
			return errors.New("vault: ambigious authentication: AppRole and K8S credentials specified at the same time")
		}
		authenticate = s.client.AuthenticateWithK8S(s.K8S)
	default:
		return errors.New("vault: no or empty authentication credentials specified")
	}

	token, ttl, err := authenticate()
	if err != nil {
		return err
	}
	s.client.SetToken(token)

	go s.client.CheckStatus(context, s.StatusPingAfter)
	go s.client.RenewToken(context, authenticate, ttl, retry)
	return nil
}

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")

	errSealed = errors.New("vault: key store is sealed")
)

const (
	// EngineV1 is the Hashicorp Vault K/V secret engine version 1.
	// This K/V secret store is not versioned.
	EngineV1 = "v1"

	// EngineV2 is the Hashicorp Vault K/V secret engine version 2.
	// This K/V secret store is versioned.
	EngineV2 = "v2"
)

// Create creates the given key-value pair at Vault if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *Store) Create(ctx context.Context, name string, key key.Key) error {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.Addr)
		return errCreateKey
	}
	if s.client.Sealed() {
		return errSealed
	}

	// We try to check whether key exists on the K/V store.
	// If so, we must not overwrite it.
	var location string
	if s.EngineVersion == EngineV2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#create-update-secret
		location = path.Join(s.Engine, "data", s.Location, name) // /<engine>/data/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#create-update-secret
		location = path.Join(s.Engine, s.Location, name) // /<engine>/<location>/<name>
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
	case err == nil && secret != nil && s.EngineVersion != EngineV2:
		if _, ok := secret.Data[name]; !ok {
			s.logf("vault: entry exist but failed to read %q: invalid K/V v1 format", location)
			return errors.New("vault: invalid K/V v1 format")
		}
		return kes.ErrKeyExists
	case err == nil && secret != nil && s.EngineVersion == EngineV2 && len(secret.Data) > 0:
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
	if s.EngineVersion == EngineV2 {
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
func (s *Store) Get(_ context.Context, name string) (key.Key, error) {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.Addr)
		return key.Key{}, errGetKey
	}
	if s.client.Sealed() {
		return key.Key{}, errSealed
	}

	var location string
	if s.EngineVersion == EngineV2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#read-secret-version
		location = path.Join(s.Engine, "data", s.Location, name) // /<engine>/data/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#read-secret
		location = path.Join(s.Engine, s.Location, name) // /<engine>/<location>/<name>
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
	if s.EngineVersion == EngineV2 { // See: https://www.vaultproject.io/api/secret/kv/kv-v2#sample-response-1 (differs from v1 format)
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
func (s *Store) Delete(ctx context.Context, name string) error {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.Addr)
		return errDeleteKey
	}
	if s.client.Sealed() {
		return errSealed
	}

	var location string
	if s.EngineVersion == EngineV2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#delete-metadata-and-all-versions
		location = path.Join(s.Engine, "metadata", s.Location, name) // /<engine>/metadata/<location>/<name>
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#delete-secret
		location = path.Join(s.Engine, s.Location, name) // /<engine>/<location>/<name>
	}

	// The Vault SDK may not return an error even if it hasn't deleted
	// an entry - e.g. in case of some network errors. Therefore, we
	// implement the specific key deletion logic ourself.
	//
	// We expect HTTP 204 (No Content) when a key got deleted successfully.
	// So, we check that Vault response with 204. Otherwise, we return an
	// error.
	var req = s.client.Client.NewRequest("DELETE", "/v1/"+location)
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
func (s *Store) List(ctx context.Context) (key.Iterator, error) {
	if s.client == nil {
		s.logf("vault: no connection to vault server: %q", s.Addr)
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
	if s.EngineVersion == EngineV2 {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v2#list-secrets
		location = path.Join("/v1", s.Engine, "metadata", s.Location)
	} else {
		// See: https://www.vaultproject.io/api/secret/kv/kv-v1#list-secrets
		location = path.Join("/v1", s.Engine, s.Location)
	}
	r := s.client.NewRequest("LIST", location)
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

type iterator struct {
	values []interface{}
	last   string
}

var _ key.Iterator = (*iterator)(nil)

func (i *iterator) Next() bool {
	for len(i.values) > 0 {
		v := fmt.Sprint(i.values[0])
		i.values = i.values[1:]

		if !strings.HasSuffix(v, "/") {
			i.last = v
			return true
		}
	}
	return false
}

func (i *iterator) Name() string { return i.last }

func (*iterator) Err() error { return nil }

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}
