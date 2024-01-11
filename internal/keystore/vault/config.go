// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"sync"
	"time"
)

const (
	// APIv1 is the Vault K/V secret engine API version 1.
	// The v1 K/V secret engine does not support version'ed
	// secrets.
	APIv1 = "v1"

	// APIv2 is the Vault K/V secret engine API version 2.
	// The v1 K/V secret engine supports version'ed secrets.
	APIv2 = "v2"
)

const (
	// EngineKV is the Hashicorp Vault default KV secret engine path.
	EngineKV = "kv"

	// EngineTransit is the Hashicorp Vault default transit secret engine path.
	EngineTransit = "transit"

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

	// Namespace is the Vault namespace in which the AppRole
	// authentication is performed. It can be used to authenticate
	// in a different namespace compared to the secret engine
	// namespace. For example, authenticate within the root
	// namespace but use a team-specific namespace for the secret
	// engine.
	//
	// If empty, the VaultKeyStore namespace is used, if set.
	// A single "/" is treated as alias for the Vault root
	// namespace such that no namespace header is sent as part
	// of the request.
	Namespace string

	// ID is the AppRole authentication ID
	ID string

	// Secret is the AppRole authentication secret.
	Secret string
}

// Clone returns a copy of the AppRole auth.
func (a *AppRole) Clone() *AppRole {
	if a == nil {
		return nil
	}
	return &AppRole{
		Engine:    a.Engine,
		Namespace: a.Namespace,
		ID:        a.ID,
		Secret:    a.Secret,
	}
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

	// Namespace is the Vault namespace in which the Kubernetes
	// authentication is performed. It can be used to authenticate
	// in a different namespace compared to the secret engine
	// namespace. For example, authenticate within the root
	// namespace but use a team-specific namespace for the secret
	// engine.
	//
	// If empty, the VaultKeyStore namespace is used, if set.
	// A single "/" is treated as alias for the Vault root
	// namespace such that no namespace header is sent as part
	// of the request.
	Namespace string

	// Role is the JWT role.
	Role string

	// JWT is the issued authentication token.
	JWT string
}

// Clone returns a copy of the Kubernetes auth.
func (k *Kubernetes) Clone() *Kubernetes {
	if k == nil {
		return nil
	}
	return &Kubernetes{
		Engine:    k.Engine,
		Namespace: k.Namespace,
		Role:      k.Role,
		JWT:       k.JWT,
	}
}

// Transit contains information for using the
// Hashicorp Vault transit encryption engine.
//
// Ref: https://developer.hashicorp.com/vault/api-docs/secret/transit
type Transit struct {
	// Engine is the transit engine path.
	// If empty, defaults to EngineTransit.
	Engine string

	// KeyName is the name of the transit key
	// used for en/decrypting K/V entries.
	KeyName string
}

// Clone returns a copy of the Transit.
func (t *Transit) Clone() *Transit {
	if t == nil {
		return nil
	}
	return &Transit{
		Engine:  t.Engine,
		KeyName: t.KeyName,
	}
}

// Config is a structure containing configuration
// options for connecting to a Hashicorp Vault server.
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
	AppRole *AppRole

	// K8S contains the Vault Kubernetes authentication
	// credentials.
	K8S *Kubernetes

	// Transit contains an optional Vault transit engine
	// configuration for en/decrypting keys at the K/V
	// engine. It adds an additional layer of encryption.
	Transit *Transit

	// StatusPingAfter is the duration after which
	// the KeyStore will check the status of the Vault
	// server. Particularly, this status information
	// is used to determine whether the Vault server
	// has been sealed resp. unsealed again.
	StatusPingAfter time.Duration

	// Path to the mTLS client private key to authenticate to
	// the Vault server.
	PrivateKey string

	// Path to the mTLS client certificate to authenticate to
	// the Vault server.
	Certificate string

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
		AppRole:         c.AppRole.Clone(),
		K8S:             c.K8S.Clone(),
		Transit:         c.Transit.Clone(),
		StatusPingAfter: c.StatusPingAfter,
		PrivateKey:      c.PrivateKey,
		Certificate:     c.Certificate,
		CAPath:          c.CAPath,
	}
}
