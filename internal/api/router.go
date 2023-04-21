// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
)

// RouterConfig is a structure containing the
// API configuration for a KES server.
type RouterConfig struct {
	Vault *sys.Vault

	Metrics *metric.Metrics

	Proxy *auth.TLSProxy

	AuditLog *log.Logger

	ErrorLog *log.Logger
}

// EdgeRouterConfig is a structure containing the
// API configuration for a KES edge server.
type EdgeRouterConfig struct {
	Keys *key.Cache

	Policies auth.PolicySet

	Identities auth.IdentitySet

	Metrics *metric.Metrics

	Proxy *auth.TLSProxy

	APIConfig map[string]Config

	AuditLog *log.Logger

	ErrorLog *log.Logger
}

// NewRouter returns a new API Router for a KES
// server with the given configuration.
func NewRouter(config *RouterConfig) *Router {
	r := &Router{
		handler: http.NewServeMux(),
	}

	r.api = append(r.api, version(config))
	r.api = append(r.api, status(config))
	r.api = append(r.api, metrics(config))
	r.api = append(r.api, listAPI(r, config))

	r.api = append(r.api, createKey(config))
	r.api = append(r.api, importKey(config))
	r.api = append(r.api, describeKey(config))
	r.api = append(r.api, listKey(config))
	r.api = append(r.api, deleteKey(config))
	r.api = append(r.api, encryptKey(config))
	r.api = append(r.api, generateKey(config))
	r.api = append(r.api, decryptKey(config))
	r.api = append(r.api, bulkDecryptKey(config))

	r.api = append(r.api, createSecret(config))
	r.api = append(r.api, describeSecret(config))
	r.api = append(r.api, readSecret(config))
	r.api = append(r.api, deleteSecret(config))
	r.api = append(r.api, listSecret(config))

	r.api = append(r.api, assignPolicy(config))
	r.api = append(r.api, describePolicy(config))
	r.api = append(r.api, readPolicy(config))
	r.api = append(r.api, writePolicy(config))
	r.api = append(r.api, deletePolicy(config))
	r.api = append(r.api, listPolicy(config))

	r.api = append(r.api, describeIdentity(config))
	r.api = append(r.api, selfDescribeIdentity(config))
	r.api = append(r.api, listIdentity(config))
	r.api = append(r.api, deleteIdentity(config))

	r.api = append(r.api, createEnclave(config))
	r.api = append(r.api, describeEnclave(config))
	r.api = append(r.api, deleteEnclave(config))

	r.api = append(r.api, errorLog(config))
	r.api = append(r.api, auditLog(config))

	for _, a := range r.api {
		r.handler.Handle(a.Path, proxy(config.Proxy, a))
	}
	r.handler.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		Fail(w, kes.NewError(http.StatusNotImplemented, "not implemented"))
	}))
	return r
}

// NewEdgeRouter returns a new API Router for a KES edge
// server with the given configuration.
func NewEdgeRouter(config *EdgeRouterConfig) *Router {
	r := &Router{
		handler: http.NewServeMux(),
	}

	r.api = append(r.api, edgeVersion(config))
	r.api = append(r.api, edgeReady(config))
	r.api = append(r.api, edgeStatus(config))
	r.api = append(r.api, edgeMetrics(config))
	r.api = append(r.api, edgeListAPI(r, config))

	r.api = append(r.api, edgeCreateKey(config))
	r.api = append(r.api, edgeImportKey(config))
	r.api = append(r.api, edgeDescribeKey(config))
	r.api = append(r.api, edgeDeleteKey(config))
	r.api = append(r.api, edgeListKey(config))
	r.api = append(r.api, edgeGenerateKey(config))
	r.api = append(r.api, edgeEncryptKey(config))
	r.api = append(r.api, edgeDecryptKey(config))
	r.api = append(r.api, edgeBulkDecryptKey(config))

	r.api = append(r.api, edgeDescribePolicy(config))
	r.api = append(r.api, edgeReadPolicy(config))
	r.api = append(r.api, edgeListPolicy(config))

	r.api = append(r.api, edgeDescribeIdentity(config))
	r.api = append(r.api, edgeSelfDescribeIdentity(config))
	r.api = append(r.api, edgeListIdentity(config))

	r.api = append(r.api, edgeErrorLog(config))
	r.api = append(r.api, edgeAuditLog(config))

	for _, a := range r.api {
		r.handler.Handle(a.Path, proxy(config.Proxy, a))
	}
	r.handler.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		Fail(w, kes.NewError(http.StatusNotImplemented, "not implemented"))
	}))
	return r
}

// Router is an HTTP handler that implements the KES API.
//
// It routes incoming HTTP requests and invokes the
// corresponding API handlers.
type Router struct {
	handler *http.ServeMux
	api     []API
}

// ServeHTTP dispatches the request to the API handler whose
// pattern most matches the request URL.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, "/") { // Ensure URL paths start with a '/'
		req.URL.Path = "/" + req.URL.Path
	}
	r.handler.ServeHTTP(w, req)
}

// API returns a list of APIs provided by the Router.
func (r *Router) API() []API { return r.api }

// A HandlerFunc is an adapter that allows the use of
// ordinary functions as HTTP handlers.
//
// In contrast to the http.HandlerFunc type, HandlerFunc
// returns an error. Hence, a function f, with the appropriate
// signature, can simply return an error in case of failed
// operation. If f returns a non-nil error, HandlerFunc(f)
// sends an error response to the client.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP calls f(w, r). If f returns a non-nil error
// ServeHTTP sends an error response to the client.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f(w, r); err != nil {
		Fail(w, err)
	}
}
