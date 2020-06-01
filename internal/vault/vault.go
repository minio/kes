// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
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
	"net/http"
	"os"
	"path"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/minio/kes"
)

// AppRole holds the Vault AppRole
// authentication credentials and
// a duration after which the
// authentication should be retried
// whenever it fails.
type AppRole struct {
	Engine string // The AppRole engine path
	ID     string // The AppRole  ID
	Secret string // The Approle secret ID
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
			return fmt.Errorf("Failed to open '%s': %v", s.CAPath, err)
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
	go s.client.CheckStatus(context, s.StatusPingAfter)

	token, ttl, err := s.client.Authenticate(s.AppRole)
	if err != nil {
		return err
	}
	s.client.SetToken(token)
	go s.client.RenewToken(context, s.AppRole, ttl)
	return nil
}

var errSealed = kes.NewError(http.StatusForbidden, "key store is sealed")

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(key string) (string, error) {
	if s.client == nil {
		s.log(errNoConnection)
		return "", errNoConnection
	}
	if s.client.Sealed() {
		return "", errSealed
	}

	location := path.Join(s.Engine, s.Location, key) // /<engine>/<location>/<key>
	entry, err := s.client.Logical().Read(location)
	if err != nil || entry == nil {
		// Vault will not return an error if e.g. the key existed but has
		// been deleted. However, it will return (nil, nil) in this case.
		if err == nil && entry == nil {
			return "", kes.ErrKeyNotFound
		}
		s.logf("vault: failed to read '%s': %v", location, err)
		return "", err
	}

	// Verify that we got a well-formed response from Vault
	v, ok := entry.Data[key]
	if !ok || v == nil {
		s.logf("vault: failed to read '%s': entry exists but no secret key is present", location)
		return "", errors.New("vault: K/V entry does not contain any value")
	}
	value, ok := v.(string)
	if !ok {
		s.logf("vault: failed to read '%s': invalid K/V format", location)
		return "", errors.New("vault: invalid K/V entry format")
	}
	return value, nil
}

// Create creates the given key-value pair at Vault if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *Store) Create(key, value string) error {
	if s.client == nil {
		s.log(errNoConnection)
		return errNoConnection
	}
	if s.client.Sealed() {
		return errSealed
	}

	// We try to check whether key exists on the K/V store.
	// If so, we must not overwrite it.
	location := path.Join(s.Engine, s.Location, key) // /<engine>/<location>/<key>

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
	switch secret, err := s.client.Logical().Read(location); {
	case err == nil && secret != nil:
		return kes.ErrKeyExists
	case err != nil:
		s.logf("vault: failed to create '%s': %v", location, err)
		return err
	}

	// Finally, we create the value since it seems that it
	// doesn't exist. However, this is just an assumption since
	// another key server may have created that key in the meantime.
	// Since there is now way we can detect that reliable we require
	// that whoever has the permission to create keys does that in
	// a non-racy way.
	_, err := s.client.Logical().Write(location, map[string]interface{}{
		key: value,
	})
	if err != nil {
		s.logf("vault: failed to create '%s': %v", location, err)
		return err
	}
	return nil
}

// Delete removes a the value associated with the given key
// from Vault, if it exists.
func (s *Store) Delete(key string) error {
	if s.client == nil {
		s.log(errNoConnection)
		return errNoConnection
	}
	if s.client.Sealed() {
		return errSealed
	}

	// Vault will not return an error if an entry does not
	// exist. Instead, it responds with 204 No Content and
	// no body. In this case the client also returns a nil-error
	// Therefore, we can just try to delete it in any case.
	location := path.Join(s.Engine, s.Location, key) // /<engine>/<location>/<key>
	_, err := s.client.Logical().Delete(location)
	if err != nil {
		s.logf("vault: failed to delete '%s': %v", location, err)
	}
	return err
}

// errNoConnection is the error returned and logged by
// the key store if the vault client hasn't been initialized.
//
// This error is returned by Create, Get, Delete, a.s.o.
// in case of an invalid configuration - i.e. when Authenticate()
// hasn't been called.
var errNoConnection = errors.New("vault: no connection to vault server")

func (s *Store) log(v ...interface{}) {
	if s.ErrorLog == nil {
		log.Println(v...)
	} else {
		s.ErrorLog.Println(v...)
	}
}

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}
