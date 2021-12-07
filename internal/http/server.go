// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
	"time"

	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
)

// A ServerConfig structure is used to configure a
// KES server.
type ServerConfig struct {
	// Version is the KES server version.
	// If empty, it defaults to v0.0.0-dev.
	Version string

	// Manager is the key manager that fetches
	// keys from a key store and stores them
	// in a local in-memory cache.
	Manager *key.Manager

	// Roles is the authorization system that
	// contains identities and the associated
	// policies.
	Roles *auth.Roles

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
	var (
		version  = config.Version
		manager  = config.Manager
		roles    = config.Roles
		proxy    = config.Proxy
		auditLog = config.AuditLog
		errorLog = config.ErrorLog
		metrics  = config.Metrics
	)
	if version == "" {
		version = "v0.0.0-dev"
	}

	const MaxBody = 1 << 20
	var mux = http.NewServeMux()
	mux.Handle("/v1/key/create/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/key/create/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleCreateKey(manager)))))))))))
	mux.Handle("/v1/key/import/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/key/import/*", limitRequestBody(MaxBody, tlsProxy(proxy, enforcePolicies(roles, handleImportKey(manager)))))))))))
	mux.Handle("/v1/key/delete/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodDelete, validatePath("/v1/key/delete/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleDeleteKey(manager)))))))))))
	mux.Handle("/v1/key/generate/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/key/generate/*", limitRequestBody(MaxBody, tlsProxy(proxy, enforcePolicies(roles, handleGenerateKey(manager)))))))))))
	mux.Handle("/v1/key/encrypt/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/key/encrypt/*", limitRequestBody(MaxBody/2, tlsProxy(proxy, enforcePolicies(roles, handleEncryptKey(manager)))))))))))
	mux.Handle("/v1/key/decrypt/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/key/decrypt/*", limitRequestBody(MaxBody, tlsProxy(proxy, enforcePolicies(roles, handleDecryptKey(manager)))))))))))
	mux.Handle("/v1/key/list/", timeout(15*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/key/list/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleListKeys(manager)))))))))))

	mux.Handle("/v1/policy/write/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/policy/write/*", limitRequestBody(MaxBody, tlsProxy(proxy, enforcePolicies(roles, handleWritePolicy(roles)))))))))))
	mux.Handle("/v1/policy/read/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/policy/read/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleReadPolicy(roles)))))))))))
	mux.Handle("/v1/policy/list/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/policy/list/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleListPolicies(roles)))))))))))
	mux.Handle("/v1/policy/delete/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodDelete, validatePath("/v1/policy/delete/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleDeletePolicy(roles)))))))))))

	mux.Handle("/v1/identity/assign/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodPost, validatePath("/v1/identity/assign/*/*", limitRequestBody(MaxBody, tlsProxy(proxy, enforcePolicies(roles, handleAssignIdentity(roles)))))))))))
	mux.Handle("/v1/identity/list/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/identity/list/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleListIdentities(roles)))))))))))
	mux.Handle("/v1/identity/forget/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodDelete, validatePath("/v1/identity/forget/*", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleForgetIdentity(roles)))))))))))

	mux.Handle("/v1/log/audit/trace", metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/log/audit/trace", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleTraceAuditLog(auditLog))))))))))
	mux.Handle("/v1/log/error/trace", metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/log/error/trace", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleTraceErrorLog(errorLog))))))))))

	mux.Handle("/v1/status", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/v1/status", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleStatus(version, manager, errorLog)))))))))))

	// Scrapping /v1/metrics should not change the metrics itself.
	// Further, scrapping /v1/metrics should, by default, not produce
	// an audit event. Monitoring systems will scrape the metrics endpoint
	// every few seconds - depending on their configuration - such that
	// the audit log will contain a lot of events simply pointing to the
	// monitoring system. Logging an audit event may be something that
	// can be enabled optionally.
	mux.Handle("/v1/metrics", timeout(10*time.Second, requireMethod(http.MethodGet, validatePath("/v1/metrics", limitRequestBody(0, tlsProxy(proxy, enforcePolicies(roles, handleMetrics(metrics))))))))

	mux.Handle("/version", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, requireMethod(http.MethodGet, validatePath("/version", limitRequestBody(0, tlsProxy(proxy, handleVersion(version)))))))))) // /version is accessible to any identity
	mux.Handle("/", timeout(10*time.Second, metrics.Count(metrics.Latency(audit(auditLog.Log(), roles, tlsProxy(proxy, http.NotFound))))))
	return mux
}
