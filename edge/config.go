// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"crypto/tls"
	"time"

	"github.com/minio/kes-go"
	"golang.org/x/exp/slog"
)

// Config is a structure that holds configuration
// for a KES edge server.
type Config struct {
	// Addr optionally specifies the TCP address for the
	// KES server to listen on, in the form "host:port".
	//
	// If empty, ":7373" is used causing the server to
	// listen on all network interfaces on port "7373".
	//
	// When Addr contains a host, the KES server will
	// listen only on the referred network interface.
	// For example, "127.0.0.1:7373" causes the server
	// to listen only on the local loopback interface
	// on port "7373".
	Addr string

	// Admin is the KES server admin identity.
	Admin kes.Identity

	// TLS contains the KES server's TLS configuration
	TLS *tls.Config

	Cache *CacheConfig

	Policies map[string]*kes.Policy

	Identities map[kes.Identity]string

	API map[string]APIConfig

	ErrorLog slog.Handler

	AuditLog slog.Handler
}

func (c *Config) Clone() *Config {
	return c
}

type TLSProxy struct {
	Identities          []kes.Identity
	ForwardedCertHeader string
}

// APIConfig is a structure that holds the API configuration
// for one particular KES API.
type APIConfig struct {
	// Timeout is the duration after which the API response
	// with a HTTP timeout error response. If Timeout is
	// zero the API default is used.
	Timeout time.Duration

	// InsecureSkipAuth controls whether the API verifies
	// client identities. If InsecureSkipAuth is true,
	// the API accepts requests from arbitrary identities.
	// In this mode, the API can be used by anyone who can
	// communicate to the KES server over HTTPS.
	// This should only be set for testing or in certain
	// cases for APIs that don't expose sensitive information,
	// like metrics.
	InsecureSkipAuth bool
}
