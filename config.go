// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"crypto/tls"
	"time"

	"github.com/minio/kes-go"
	"golang.org/x/exp/slog"
)

const (
	DefaultHeartbeatInterval = 500 * time.Millisecond
	DefaultElectionTimeout   = 1500 * time.Millisecond
)

// Config is a structure containing KES Node configuration.
type Config struct {
	// Addr optionally specifies the TCP address for the Node's
	// HTTP server to listen on, in the form "host:port". If empty,
	// ":https" (port 443) is used.
	// The service names are defined in RFC 6335 and assigned by IANA.
	// See net.Dial for details of the address format.
	Addr string

	// Admin is the cluster admin identity.
	//
	// The cluster admin has root-level control over the cluster
	// and can perform arbitrary operations.
	//
	// If empty, cluster admin access is disabled.
	Admin kes.Identity

	// HSM is the HSM that seals and unseals the Node's encrypted
	// database and generates the API key used to authenticate
	// the communication between the cluster nodes.
	HSM HSM

	// TLS specifies the TLS configuration to use when handling
	// client requests.
	//
	// A KES Node only accepts TLS connections. Therefore, its
	// TLS configuration must contain at least one valid server
	// certificate.
	TLS *tls.Config

	// HeartbeatInterval specifies how often the cluster leader
	// sends heartbeat ticks to its followers. If 0, defaults to
	// DefaultHeartbeatInterval.
	//
	// The HeartbeatInterval should be significantly smaller than
	// the ElectionTimeout. Otherwise, follower nodes may start
	// unnecessary leader elections.
	//
	// Smaller values increase the frequency of heartbeat ticks
	// sent by the cluster leader. When choosing a custom value,
	// a reasonable estimate is twice the network latency between
	// the cluster nodes.
	HeartbeatInterval time.Duration

	// ElectionTimeout is the time period after which follower
	// nodes start a leader election unless they have received
	// a heartbeat event from a leader. It must be greater than
	// the heartbeat interval. If 0, defaults to DefaultElectionTimeout.
	//
	// The ElectionTimeout should be significantly larger than
	// the HeartbeatInterval. Otherwise, follower nodes may start
	// unnecessary leader elections.
	//
	// Smaller values reduce the time window in which the cluster
	// operates without a leader, unable to process write requests,
	// in case of a leader crash. When choosing a custom value,
	// a reasonable estimate is at least twice the heartbeat interval.
	ElectionTimeout time.Duration

	ErrorLog slog.Handler

	AuditLog slog.Handler
}
