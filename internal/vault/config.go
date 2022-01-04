// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"log"
	"sync"
	"time"
)

const (
	APIv1 = "v1"
	APIv2 = "v2"
)

const (
	// EngineKV is the Hashicorp Vault default KV secret engine path.
	EngineKV = "kv"

	// EngineAppRole is the Hashicorp Vault default AppRole authentication
	// engine path.
	EngineAppRole = "approle"

	// EngineKubernetes is the Hashicorp Vault default Kubernetes
	// authentication engine path.
	EngineKubernetes = "kubernetes"
)

// AppRole contains authentication information
// for the Hashicorp Vault AppRole authentication
// API.
//
// Ref: https://www.vaultproject.io/api/auth/approle
type AppRole struct {
	// Engine is the authentication engine path
	//
	// Hashicorp Vault allows multiple engines of the
	// same type mounted at the same time and/or engines
	// mounted at arbitrary paths.
	Engine string

	// ID is the AppRole authentication ID
	ID string

	// Secret is the AppRole authentication secret.
	Secret string

	// Retry is the duration after which another
	// authentication attempt is performed once
	// an authentication attempt failed.
	Retry time.Duration
}

// Kubernetes contains authentication information
// for the Hashicorp Vault Kubernetes authentication
// API.
//
// Ref: https://www.vaultproject.io/api/auth/kubernetes
type Kubernetes struct {
	// Engine is the authentication engine path
	//
	// Hashicorp Vault allows multiple engines of the
	// same type mounted at the same time and/or engines
	// mounted at arbitrary paths.
	Engine string

	// Role is the JWT role.
	Role string

	// JWT is the issued authentication token.
	JWT string

	// Retry is the duration after which another
	// authentication attempt is performed once
	// an authentication attempt failed.
	Retry time.Duration
}

// A Config structure is used to configure a Hashicorp Vault
// client.
type Config struct {
	// Endpoint is the HTTP Vault server endpoint
	Endpoint string

	// Engine is the path of the K/V engine to use.
	//
	// Vault allows multiple engines of the same type
	// mounted at the same time and/or engines mounted
	// at arbitrary paths.
	Engine string

	// APIVersion is the API version of the K/V engine.
	//
	// If empty, it defaults to APIv1.
	//
	// Ref: https://www.vaultproject.io/docs/secrets/kv
	APIVersion string

	// The Vault namespace used to separate and isolate different
	// organizations / tenants at the same Vault instance. If
	// non-empty, the Vault client will send the
	//   X-Vault-Namespace: Namespace
	// HTTP header on each request.
	//
	// Ref: https://www.vaultproject.io/docs/enterprise/namespaces/index.html
	Namespace string

	// Prefix is the key prefix on Vault's K/V store
	// similar to a directory. Keys will be fetched
	// from and stored within this prefix.
	Prefix string

	// AppRole contains the Vault AppRole authentication
	// credentials.
	AppRole AppRole

	// K8S contains the Vault Kubernetes authentication
	// credentials.
	K8S Kubernetes

	// ErrorLog is an optional logger for errors that
	// may occur when interacting with an Hashicorp
	// Vault server.
	ErrorLog *log.Logger

	// StatusPingAfter is the duration after which
	// the KeyStore will check the status of the Vault
	// server. Particularly, this status information
	// is used to determine whether the Vault server
	// has been sealed resp. unsealed again.
	StatusPingAfter time.Duration

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

	lock sync.RWMutex
}

// Clone returns a shallow clone of c or nil if c is
// nil. It is safe to clone a Config that is being used
// concurrently.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	return &Config{
		Endpoint:        c.Endpoint,
		Engine:          c.Engine,
		APIVersion:      c.APIVersion,
		Namespace:       c.Namespace,
		Prefix:          c.Prefix,
		AppRole:         c.AppRole,
		K8S:             c.K8S,
		ErrorLog:        c.ErrorLog,
		StatusPingAfter: c.StatusPingAfter,
		ClientKeyPath:   c.ClientKeyPath,
		ClientCertPath:  c.ClientCertPath,
		CAPath:          c.CAPath,
	}
}

// setDefaults overwrites some empty fields with
// default values.
func (c *Config) setDefaults() {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.Engine == "" {
		c.Engine = EngineKV
	}
	if c.APIVersion == "" {
		c.APIVersion = APIv1
	}
	if c.AppRole.Retry == 0 {
		c.AppRole.Retry = 5 * time.Second
	}
	if c.K8S.Engine == "" {
		c.K8S.Engine = EngineKubernetes
	}
	if c.K8S.Retry == 0 {
		c.K8S.Retry = 5 * time.Second
	}
}
