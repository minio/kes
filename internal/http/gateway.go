// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
	"time"

	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
)

// A GatewayConfig structure is used to configure a
// KES gateway.
type GatewayConfig struct {
	Proxy *auth.TLSProxy

	AuditLog *log.Logger

	ErrorLog *log.Logger

	Metrics *metric.Metrics

	Keys *key.Cache

	Policies auth.PolicySet

	Identities auth.IdentitySet

	APIs []API
}

// NewGatewayMux returns a new KES gateway handler that
// uses the given GatewayConfig to implement the KES
// HTTP API.
func NewGatewayMux(config *GatewayConfig) *http.ServeMux {
	mux := http.NewServeMux()
	config.APIs = append(config.APIs, gatewayVersion(mux, config))
	config.APIs = append(config.APIs, gatewayStatus(mux, config))
	config.APIs = append(config.APIs, gatewayMetrics(mux, config))
	config.APIs = append(config.APIs, gatewayListAPIs(mux, config))

	config.APIs = append(config.APIs, gatewayCreateKey(mux, config))
	config.APIs = append(config.APIs, gatewayImportKey(mux, config))
	config.APIs = append(config.APIs, gatewayDescribeKey(mux, config))
	config.APIs = append(config.APIs, gatewayDeleteKey(mux, config))
	config.APIs = append(config.APIs, gatewayGenerateKey(mux, config))
	config.APIs = append(config.APIs, gatewayEncryptKey(mux, config))
	config.APIs = append(config.APIs, gatewayDecryptKey(mux, config))
	config.APIs = append(config.APIs, gatewayBulkDecryptKey(mux, config))
	config.APIs = append(config.APIs, gatewayListKey(mux, config))

	config.APIs = append(config.APIs, gatewayDescribePolicy(mux, config))
	config.APIs = append(config.APIs, gatewayReadPolicy(mux, config))
	config.APIs = append(config.APIs, gatewayListPolicy(mux, config))

	config.APIs = append(config.APIs, gatewayDescribeIdentity(mux, config))
	config.APIs = append(config.APIs, gatewaySelfDescribeIdentity(mux, config))
	config.APIs = append(config.APIs, gatewayListIdentities(mux, config))

	config.APIs = append(config.APIs, gatewayErrorLog(mux, config))
	config.APIs = append(config.APIs, gatewayAuditLog(mux, config))

	mux.HandleFunc("/", timeout(10*time.Second, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented", http.StatusNotImplemented)
	}))
	return mux
}
