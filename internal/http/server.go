// Copyright 2021 - MinIO, Inc. All rights reserved.
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
	// Version is the KES server version.
	// If empty, it defaults to v0.0.0-dev.
	Version string

	// Store is the key store holding the cryptographic
	// keys.
	Vault sys.Vault

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
}

// NewServerMux returns a new KES server handler that
// uses the given ServerConfig to implement the KES
// HTTP API.
func NewServerMux(config *ServerConfig) *http.ServeMux {
	if config.Version == "" {
		config.Version = "v0.0.0-dev"
	}

	const MaxBody = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/key/create/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleCreateKey(config)))))))))))
	mux.Handle("/v1/key/import/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/key/import/*", limitRequestBody(MaxBody, tlsProxy(config.Proxy, enforcePolicies(config, handleImportKey(config)))))))))))
	mux.Handle("/v1/key/delete/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodDelete, validatePath("/v1/key/delete/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleDeleteKey(config)))))))))))
	mux.Handle("/v1/key/generate/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/key/generate/*", limitRequestBody(MaxBody, tlsProxy(config.Proxy, enforcePolicies(config, handleGenerateKey(config)))))))))))
	mux.Handle("/v1/key/encrypt/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/key/encrypt/*", limitRequestBody(MaxBody/2, tlsProxy(config.Proxy, enforcePolicies(config, handleEncryptKey(config)))))))))))
	mux.Handle("/v1/key/decrypt/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/key/decrypt/*", limitRequestBody(MaxBody, tlsProxy(config.Proxy, enforcePolicies(config, handleDecryptKey(config)))))))))))
	mux.Handle("/v1/key/list/", timeout(15*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/key/list/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleListKeys(config)))))))))))

	mux.Handle("/v1/policy/assign/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/policy/assign/*", limitRequestBody(MaxBody, tlsProxy(config.Proxy, enforcePolicies(config, handleAssignPolicy(config)))))))))))
	mux.Handle("/v1/policy/write/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodPost, validatePath("/v1/policy/write/*", limitRequestBody(MaxBody, tlsProxy(config.Proxy, enforcePolicies(config, handleWritePolicy(config)))))))))))
	mux.Handle("/v1/policy/read/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/policy/read/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleReadPolicy(config)))))))))))
	mux.Handle("/v1/policy/list/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/policy/list/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleListPolicies(config)))))))))))
	mux.Handle("/v1/policy/delete/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodDelete, validatePath("/v1/policy/delete/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleDeletePolicy(config)))))))))))

	mux.Handle("/v1/identity/list/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/identity/list/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleListIdentities(config)))))))))))
	mux.Handle("/v1/identity/delete/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodDelete, validatePath("/v1/identity/delete/*", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleDeleteIdentity(config)))))))))))

	mux.Handle("/v1/log/audit/trace", config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/log/audit/trace", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleTraceAuditLog(config.AuditLog))))))))))
	mux.Handle("/v1/log/error/trace", config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/log/error/trace", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleTraceErrorLog(config.ErrorLog))))))))))

	mux.Handle("/v1/status", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/v1/status", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleStatus(config)))))))))))

	// Scrapping /v1/metrics should not change the metrics itself.
	// Further, scrapping /v1/metrics should, by default, not produce
	// an audit event. Monitoring systems will scrape the metrics endpoint
	// every few seconds - depending on their configuration - such that
	// the audit log will contain a lot of events simply pointing to the
	// monitoring system. Logging an audit event may be something that
	// can be enabled optionally.
	mux.Handle("/v1/metrics", timeout(10*time.Second, requireMethod(http.MethodGet, validatePath("/v1/metrics", limitRequestBody(0, tlsProxy(config.Proxy, enforcePolicies(config, handleMetrics(config.Metrics))))))))

	mux.Handle("/version", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), requireMethod(http.MethodGet, validatePath("/version", limitRequestBody(0, tlsProxy(config.Proxy, handleVersion(config.Version)))))))))) // /version is accessible to any identity
	mux.Handle("/", timeout(10*time.Second, config.Metrics.Count(config.Metrics.Latency(audit(config.AuditLog.Log(), tlsProxy(config.Proxy, http.NotFound))))))
	return mux
}
