// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"crypto/tls"
	"errors"
	"log/slog"
	"time"

	"github.com/minio/kms-go/kes"
)

// Config is a structure that holds configuration for a KES server.
type Config struct {
	// Admin is the KES server admin identity. It must not be empty.
	// To disable admin access set it to a non-hex value. For example,
	// "disabled".
	Admin kes.Identity

	// TLS contains the KES server's TLS configuration.
	//
	// A KES server requires a TLS certificate. Therefore, either
	// Config.Certificates, Config.GetCertificate or
	// Config.GetConfigForClient must be set.
	//
	// Further, the KES server has to request client certificates
	// for mTLS authentication. Hence, Config.ClientAuth must be
	// at least tls.RequestClientCert.
	TLS *tls.Config

	// Cache specifies how long the KES server caches keys from the
	// KeyStore. If nil, caching is disabled.
	Cache *CacheConfig

	// Policies is a set of policies and identities. Each identity
	// must be assigned to a policy only once.
	Policies map[string]Policy

	// Keys is the KeyStore the KES server fetches keys from.
	Keys KeyStore

	// Routes allows customization of the KES server API routes. It
	// contains a set of API route paths, for example "/v1/status",
	// and the corresponding route configuration.
	//
	// The KES server uses sane defaults for all its API routes.
	Routes map[string]RouteConfig

	// ErrorLog is an optional handler for handling the server's
	// error log events. If nil, defaults to a slog.TextHandler
	// writing to os.Stderr. The server's error log level is
	// controlled by Server.ErrLevel.
	ErrorLog slog.Handler

	// AuditLog is an optional handler for handling the server's
	// audit log events. If nil, defaults to a slog.TextHandler
	// writing to os.Stdout. The server's audit log level is
	// controlled by Server.AuditLevel.
	AuditLog AuditHandler
}

// Policy is a KES policy with associated identities.
//
// A policy contains a set of allow and deny rules.
type Policy struct {
	Allow map[string]kes.Rule // Set of allow rules

	Deny map[string]kes.Rule // Set of deny rules

	Identities []kes.Identity
}

// CacheConfig is a structure containing the KES server
// key store cache configuration.
type CacheConfig struct {
	// Expiry controls how long a particular key resides
	// in the cache. If zero or negative, keys remain in
	// the cache as long as the KES server has sufficient
	// memory.
	Expiry time.Duration

	// ExpiryUnused is the interval in which a particular
	// key must be accessed to remain in the cache. Keys
	// that haven't been accessed get evicted from the
	// cache. The general cache expiry still applies.
	//
	// ExpiryUnused does nothing if <= 0 or greater than
	// Expiry.
	ExpiryUnused time.Duration

	// ExpiryOffline controls how long a particular key
	// resides in the cache once the key store becomes
	// unavailable. It overwrites Expiry and ExpiryUnused
	// if the key store is not available. Once the key
	// store is available again, Expiry and ExpiryUnused,
	// if set, apply.
	//
	// A common use of ExpiryOffline is reducing the impact
	// of a key store outage, and therefore, improving
	// availability.
	//
	// Offline caching is disabled if ExpiryOffline <= 0.
	ExpiryOffline time.Duration
}

// RouteConfig is a structure holding API route configuration.
type RouteConfig struct {
	// Timeout specifies when the API handler times out.
	//
	// A handler times out when it fails to send the
	// *entire* response body to the client within the
	// given time period.
	//
	// If <= 0, timeouts are disabled for the API route.
	//
	// Disabling timeouts may leave client/server connections
	// hung or allow certain types of denial-of-service (DOS)
	// attacks.
	Timeout time.Duration

	// InsecureSkipAuth, if set, disables authentication for the
	// API route. It allows anyone that can send HTTPS requests
	// to the KES server to invoke the API.
	//
	// For example the KES readiness API authentication may be
	// disabled when the probing clients do not support mTLS
	// client authentication
	//
	// If setting InsecureSkipAuth for any API then clients that
	// do not send a client certificate during the TLS handshake
	// no longer encounter a TLS handshake error but receive a
	// HTTP error instead. In particular, when the server's TLS
	// client auth type has been set  tls.RequireAnyClientCert
	// or tls.RequireAndVerifyClientCert.
	InsecureSkipAuth bool
}

// verifyConfig reports whether the c is a valid Config
// and contains at least a TLS certificate for the server
// and a key store.
func verifyConfig(c *Config) error {
	if c == nil || c.TLS == nil || (len(c.TLS.Certificates) == 0 && c.TLS.GetCertificate == nil && c.TLS.GetConfigForClient == nil) {
		return errors.New("kes: tls config contains no server certificate")
	}
	if c.TLS.ClientAuth == tls.NoClientCert {
		return errors.New("kes: tls client auth must request client certifiate")
	}
	if c.Keys == nil {
		return errors.New("kes: config contains no key store")
	}
	return nil
}
