// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
	"time"

	"github.com/minio/kes/internal/auth"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
)

// A ServerConfig structure is used to configure a
// KES server.
type ServerConfig struct {
	// Certificate is TLS server certificate.
	Certificate *Certificate

	Vault *sys.Vault

	// Proxy is an optional TLS proxy that sits
	// in-front of this server and forwards client
	// requests.
	//
	// A TLS proxy is responsible for forwarding
	// the client certificates via a request
	// header such that this server can apply
	// the corresponding policy.
	Proxy *auth.TLSProxy

	// AuditLog is a log target that receives
	// audit log events.
	AuditLog *xlog.Target

	// ErrorLog is a log target that receives
	// error log events.
	ErrorLog *xlog.Target

	// Metrics gathers various informations about
	// the server.
	Metrics *metric.Metrics

	APIs []API
}

// NewServerMux returns a new KES server handler that
// uses the given ServerConfig to implement the KES
// HTTP API.
func NewServerMux(config *ServerConfig) *http.ServeMux {
	mux := http.NewServeMux()
	config.APIs = append(config.APIs, serverVersion(mux, config))
	config.APIs = append(config.APIs, serverStatus(mux, config))
	config.APIs = append(config.APIs, serverMetrics(mux, config))
	config.APIs = append(config.APIs, serverListAPIs(mux, config))

	config.APIs = append(config.APIs, serverCreateKey(mux, config))
	config.APIs = append(config.APIs, serverImportKey(mux, config))
	config.APIs = append(config.APIs, serverDescribeKey(mux, config))
	config.APIs = append(config.APIs, serverDeleteKey(mux, config))
	config.APIs = append(config.APIs, serverGenerateKey(mux, config))
	config.APIs = append(config.APIs, serverEncryptKey(mux, config))
	config.APIs = append(config.APIs, serverDecryptKey(mux, config))
	config.APIs = append(config.APIs, serverBulkDecryptKey(mux, config))
	config.APIs = append(config.APIs, serverListKey(mux, config))

	config.APIs = append(config.APIs, serverCreateSecret(mux, config))
	config.APIs = append(config.APIs, serverDescribeSecret(mux, config))
	config.APIs = append(config.APIs, serverReadSecret(mux, config))
	config.APIs = append(config.APIs, serverDeleteSecret(mux, config))
	config.APIs = append(config.APIs, serverListSecrets(mux, config))

	config.APIs = append(config.APIs, serverDescribePolicy(mux, config))
	config.APIs = append(config.APIs, serverAssignPolicy(mux, config))
	config.APIs = append(config.APIs, serverReadPolicy(mux, config))
	config.APIs = append(config.APIs, serverWritePolicy(mux, config))
	config.APIs = append(config.APIs, serverListPolicy(mux, config))
	config.APIs = append(config.APIs, serverDeletePolicy(mux, config))

	config.APIs = append(config.APIs, serverDescribeIdentity(mux, config))
	config.APIs = append(config.APIs, serverSelfDescribeIdentity(mux, config))
	config.APIs = append(config.APIs, serverListIdentity(mux, config))
	config.APIs = append(config.APIs, serverDeleteIdentity(mux, config))

	config.APIs = append(config.APIs, serverErrorLog(mux, config))
	config.APIs = append(config.APIs, serverAuditLog(mux, config))

	config.APIs = append(config.APIs, serverCreateEnclave(mux, config))
	config.APIs = append(config.APIs, serverDescribeEnclave(mux, config))
	config.APIs = append(config.APIs, serverDeleteEnclave(mux, config))

	config.APIs = append(config.APIs, serverSealVault(mux, config))

	mux.HandleFunc("/", timeout(10*time.Second, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	return mux
}
