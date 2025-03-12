// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/headers"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kms-go/kes"
	"github.com/prometheus/common/expfmt"
)

// An Identity should uniquely identify a client and
// is computed from the X.509 certificate presented
// by the client during the TLS handshake.
type Identity = kes.Identity

// ServerShutdownTimeout is the default time period the server
// waits while trying to shutdown gracefully before forcefully
// closing connections.
const ServerShutdownTimeout = 1 * time.Second

// Server is a KES server.
type Server struct {
	// ShutdownTimeout controls how long Server.Close
	// tries to shutdown the server gracefully without
	// interrupting any active connections.
	//
	// If 0, defaults to ServerShutdownTimeout. If
	// negative, Server.Close waits indefinitely for
	// connections to return to idle and then shut down.
	ShutdownTimeout time.Duration

	// LogFormat controls the output format of the default logger.
	LogFormat log.Format

	// ErrLevel controls which errors are logged by the server.
	// It may be adjusted after the server has been started to
	// change its logging behavior.
	//
	// Log records are passed to the Config.ErrorLog handler
	// if and only if their log level is equal or greater than
	// ErrLevel. A custom Config.ErrorLog may handle records
	// independently from this ErrLevel.
	//
	// Defaults to slog.LevelInfo which includes TLS and HTTP
	// errors when handling requests.
	ErrLevel slog.LevelVar

	// AuditLevel controls which audit events are logged by
	// the server. It may be adjusted after the server has
	// been started to change its logging behavior.
	//
	// Log records are passed to the Config.AuditLog handler
	// if and only if their log level is equal or greater than
	// AuditLevel. A custom Config.AuditLog may handle records
	// independently from this AuditLevel.
	//
	// Defaults to slog.LevelInfo.
	AuditLevel slog.LevelVar

	tls     atomic.Pointer[tls.Config]
	state   atomic.Pointer[serverState]
	handler atomic.Pointer[http.ServeMux]

	mu              sync.Mutex
	srv             *http.Server
	started, closed bool
	cErr            error
}

// Addr returns the server's listener address, or the
// empty string if the server hasn't been started.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	state := s.state.Load()
	if state == nil {
		return ""
	}
	return state.Addr.String()
}

// UpdateAdmin updates the server's admin identity.
// All other server configuration options remain
// unchanged. It returns an error if the server
// has not been started or has been closed.
func (s *Server) UpdateAdmin(admin kes.Identity) error {
	if admin.IsUnknown() {
		return errors.New("kes: admin identity is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("kes: server is closed")
	}
	if !s.started {
		return errors.New("kes: server not started")
	}

	old := s.state.Load()
	s.state.Store(&serverState{
		Addr:       old.Addr,
		StartTime:  old.StartTime,
		Admin:      admin,
		Keys:       old.Keys,
		Policies:   old.Policies,
		Identities: old.Identities,
		Metrics:    old.Metrics,
		Routes:     old.Routes,
		LogHandler: old.LogHandler,
		Log:        old.Log,
		Audit:      old.Audit,
	})
	return nil
}

// UpdateTLS updates the server's TLS configuration.
// All other server configuration options remain
// unchanged. It returns an error if the server
// has not been started or has been closed.
func (s *Server) UpdateTLS(conf *tls.Config) error {
	if conf == nil || (len(conf.Certificates) == 0 && conf.GetCertificate == nil && conf.GetConfigForClient == nil) {
		return errors.New("kes: tls config contains no server certificate")
	}
	if conf.ClientAuth == tls.NoClientCert {
		return errors.New("kes: tls client auth must request client certificate")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("kes: server is closed")
	}
	if !s.started {
		return errors.New("kes: server not started")
	}

	s.tls.Store(conf)
	return nil
}

// UpdatePolicies updates the server policies.
// All other server configuration options remain
// unchanged. It returns an error if the server
// has not been started or has been closed.
func (s *Server) UpdatePolicies(policies map[string]Policy) error {
	policySet, identitySet, err := initPolicies(policies)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errors.New("kes: server is closed")
	}
	if !s.started {
		return errors.New("kes: server not started")
	}

	old := s.state.Load()
	s.state.Store(&serverState{
		Addr:       old.Addr,
		StartTime:  old.StartTime,
		Admin:      old.Admin,
		Keys:       old.Keys,
		Policies:   policySet,
		Identities: identitySet,
		Metrics:    old.Metrics,
		Routes:     old.Routes,
		LogHandler: old.LogHandler,
		Log:        old.Log,
		Audit:      old.Audit,
	})
	return nil
}

// Update changes the server's configuration. Callers should
// close the returned io.Closer once they want to releases any
// resources allocated by the previous configuration, like open
// file handles or background go routines.
//
// For only changing the server's admin identity, TLS configuration
// or policies use [Server.UpdateAdmin], [Server.UpdateTLS] or
// [Server.UpdatePolicies]. These more specific methods are usually
// simpler to use and more efficient.
func (s *Server) Update(conf *Config) (io.Closer, error) {
	if err := verifyConfig(conf); err != nil {
		return nil, err
	}
	policySet, identitySet, err := initPolicies(conf.Policies)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("kes: server is closed")
	}
	if !s.started {
		return nil, errors.New("kes: server not started")
	}

	old := s.state.Load()
	state := &serverState{
		Addr:       old.Addr,
		StartTime:  old.StartTime,
		Admin:      conf.Admin,
		Keys:       newCache(conf.Keys, conf.Cache),
		Policies:   policySet,
		Identities: identitySet,
		Metrics:    old.Metrics,

		LogHandler: old.LogHandler,
		Log:        old.Log,
		Audit:      old.Audit,
	}

	if conf.ErrorLog != nil && conf.ErrorLog != state.LogHandler.Handler() {
		state.LogHandler = &logHandler{
			h:    conf.ErrorLog,
			text: state.LogHandler.text,
			out:  state.LogHandler.out,
		}
		state.Log = slog.New(state.LogHandler)
	}
	if conf.AuditLog != nil {
		state.Audit.h = conf.AuditLog
	}

	mux, routes := initRoutes(s, conf.Routes, state.Metrics)
	state.Routes = routes

	s.tls.Store(conf.TLS.Clone())
	s.state.Store(state)
	s.handler.Store(mux)

	return old.Keys, nil
}

// ListenAndStart listens on the TCP network address addr and
// then calls Start to start the server using the given config.
// Accepted connections are configured to enable TCP keep-alives.
//
// HTTP/2 support is only enabled if conf.TLS is configured
// with "h2" in the TLS Config.NextProtos.
//
// ListenAndStart returns once the server is closed or ctx.Done
// returns, whatever happens first. It returns the first error
// encountered while shutting down the HTTPS server and closing
// the listener, if any. It attempts to shutdown the server
// gracefully by waiting for requests to finish before closing
// the server forcefully.
func (s *Server) ListenAndStart(ctx context.Context, addr string, conf *Config) error {
	if err := verifyConfig(conf); err != nil {
		return err
	}

	if addr == "" {
		addr = ":https"
	}

	var lnConf net.ListenConfig
	listener, err := lnConf.Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	return s.serve(ctx, listener, conf)
}

// Start starts the server using the given config and accepts
// incoming HTTPS connections on the listener ln, creating a
// new service goroutine for each.
//
// HTTP/2 support is only enabled if conf.TLS is configured
// with "h2" in the TLS Config.NextProtos.
//
// Start returns once the server is closed or ctx.Done returns,
// whatever happens first. It returns the first error encountered
// while shutting down the HTTPS server and closing the listener,
// if any. It attempts to shutdown the server gracefully by waiting
// for requests to finish before closing the server forcefully.
func (s *Server) Start(ctx context.Context, ln net.Listener, conf *Config) error {
	if err := verifyConfig(conf); err != nil {
		return err
	}
	return s.serve(ctx, ln, conf)
}

// Close closes the server and underlying listener.
// It first tries to shutdown the server gracefully
// by waiting for requests to finish before closing
// the server forcefully.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return s.cErr
	}
	s.closed = true

	if s.srv == nil {
		if state := s.state.Load(); state != nil && state.Keys != nil {
			s.cErr = state.Keys.Close()
		}
		return s.cErr
	}

	shutdownTimeout := s.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = ServerShutdownTimeout
	}

	ctx := context.Background()
	if shutdownTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, shutdownTimeout)
		defer cancel()
	}

	s.cErr = s.srv.Shutdown(ctx)
	if errors.Is(s.cErr, context.Canceled) || errors.Is(s.cErr, context.DeadlineExceeded) {
		s.cErr = s.srv.Close()
	}
	if err := s.state.Load().Keys.Close(); s.cErr == nil {
		s.cErr = err
	}
	return s.cErr
}

func (s *Server) serve(ctx context.Context, ln net.Listener, conf *Config) error {
	listener, err := s.listen(ctx, ln, conf)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		s.Close()
	}()

	err = s.srv.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return s.Close()
	}
	return err
}

func (s *Server) listen(ctx context.Context, ln net.Listener, conf *Config) (net.Listener, error) {
	policySet, identitySet, err := initPolicies(conf.Policies)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, errors.New("kes: server is closed")
	}
	if s.started {
		return nil, errors.New("kes: server already started")
	}

	state := &serverState{
		Addr:       ln.Addr(),
		StartTime:  time.Now(),
		Admin:      conf.Admin,
		Keys:       newCache(conf.Keys, conf.Cache),
		Policies:   policySet,
		Identities: identitySet,
		Metrics:    metric.New(),
	}

	if conf.ErrorLog == nil {
		state.LogHandler = newLogHandler(
			newFormattedLogHandler(os.Stderr, s.LogFormat, &slog.HandlerOptions{
				Level: &s.ErrLevel,
			}),
			&s.ErrLevel,
		)
	} else {
		state.LogHandler = newLogHandler(conf.ErrorLog, &s.ErrLevel)
	}
	state.Log = slog.New(state.LogHandler)

	if conf.AuditLog == nil {
		handler := newFormattedLogHandler(os.Stdout, s.LogFormat, &slog.HandlerOptions{Level: &s.AuditLevel})
		state.Audit = newAuditLogger(&AuditLogHandler{Handler: handler}, &s.AuditLevel)
	} else {
		state.Audit = newAuditLogger(conf.AuditLog, &s.AuditLevel)
	}

	mux, routes := initRoutes(s, conf.Routes, state.Metrics)
	state.Routes = routes

	s.tls.Store(conf.TLS.Clone())
	s.state.Store(state)
	s.handler.Store(mux)

	s.srv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.handler.Load().ServeHTTP(w, r)
		}),

		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - api.Route uses http.ResponseController
		IdleTimeout:       90 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(s.state.Load().LogHandler, slog.LevelInfo), // TODO: wrap
	}
	s.started = true

	return tls.NewListener(ln, &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return s.tls.Load(), nil
		},
	}), nil
}

func (s *Server) version(resp *api.Response, req *api.Request) {
	info, err := sys.ReadBinaryInfo()
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to read server version")
		return
	}
	api.ReplyWith(resp, http.StatusOK, api.VersionResponse{
		Version: info.Version,
		Commit:  info.CommitID,
	})
}

func (s *Server) ready(resp *api.Response, req *api.Request) {
	_, err := s.state.Load().Keys.Status(req.Context())
	if _, ok := keystore.IsUnreachable(err); ok {
		s.state.Load().Log.WarnContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusGatewayTimeout, "key store is not reachable")
		return
	}
	if err != nil {
		s.state.Load().Log.WarnContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "key store is unavailable")
		return
	}
	resp.Reply(http.StatusOK)
}

func (s *Server) status(resp *api.Response, req *api.Request) {
	info, err := sys.ReadBinaryInfo()
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to read server version")
		return
	}

	var (
		latency     time.Duration
		unreachable = true
	)
	state, err := s.state.Load().Keys.Status(req.Context())
	if err == nil {
		unreachable = false
		latency = state.Latency.Round(time.Millisecond)

		if latency == 0 { // Make sure we actually send a latency even if the key store respond time is < 1ms.
			latency = 1 * time.Millisecond
		}
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	api.ReplyWith(resp, http.StatusOK, api.StatusResponse{
		Version: info.Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		UpTime:  uint64(time.Since(s.state.Load().StartTime).Round(time.Second).Seconds()),

		CPUs:       runtime.NumCPU(),
		UsableCPUs: runtime.GOMAXPROCS(0),
		HeapAlloc:  memStats.HeapAlloc,
		StackAlloc: memStats.StackSys,

		KeyStoreLatency:     latency.Milliseconds(),
		KeyStoreUnreachable: unreachable,
	})
}

func (s *Server) metrics(resp *api.Response, req *api.Request) {
	contentType := expfmt.Negotiate(req.Header)
	resp.Header().Set(headers.ContentType, string(contentType))
	resp.WriteHeader(http.StatusOK)
	s.state.Load().Metrics.EncodeTo(expfmt.NewEncoder(resp, contentType))
}

// ListAPIs is a HandlerFunc that sends the list of server API
// routes to the client.
func (s *Server) listAPIs(resp *api.Response, _ *api.Request) {
	routes := s.state.Load().Routes
	responses := make(api.ListAPIsResponse, 0, len(routes))
	for _, ro := range routes {
		responses = append(responses, api.DescribeRouteResponse{
			Method:  ro.Method,
			Path:    ro.Path,
			MaxBody: int64(ro.MaxBody),
			Timeout: int64(ro.Timeout.Truncate(time.Second).Seconds()),
		})
	}
	api.ReplyWith(resp, http.StatusOK, responses)
}

func (s *Server) createKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var cipher crypto.SecretKeyType
	if fips.Enabled || cpu.HasAESGCM() {
		cipher = crypto.AES256
	} else {
		cipher = crypto.ChaCha20
	}

	key, err := crypto.GenerateSecretKey(cipher, rand.Reader)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to generate encryption key")
		return
	}
	hmac, err := crypto.GenerateHMACKey(crypto.SHA256, rand.Reader)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to generate encryption key")
		return
	}

	if err = s.state.Load().Keys.Create(req.Context(), req.Resource, crypto.KeyVersion{
		Key:       key,
		HMACKey:   hmac,
		CreatedAt: time.Now().UTC(),
		CreatedBy: req.Identity,
	}); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to create key")
		return
	}

	const StatusOK = http.StatusOK
	s.state.Load().Audit.Log(
		fmt.Sprintf("secret key '%s' created", req.Resource),
		StatusOK,
		req,
	)
	resp.Reply(StatusOK)
}

func (s *Server) importKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var imp api.ImportKeyRequest
	if err := api.ReadBody(req, &imp); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadRequest, "invalid import key request body")
		return
	}

	var cipher crypto.SecretKeyType
	switch imp.Cipher {
	case "AES256", "AES256-GCM_SHA256":
		cipher = crypto.AES256
	case "ChaCha20", "XCHACHA20-POLY1305":
		if fips.Enabled {
			resp.Failf(http.StatusNotAcceptable, "algorithm '%s' not supported by FIPS 140-2", imp.Cipher)
			return
		}
		cipher = crypto.ChaCha20
	default:
		resp.Failf(http.StatusNotAcceptable, "algorithm '%s' is not supported", imp.Cipher)
		return
	}

	if len(imp.Bytes) != crypto.SecretKeySize {
		resp.Failf(http.StatusNotAcceptable, "invalid key size for '%s'", imp.Cipher)
		return
	}

	key, err := crypto.NewSecretKey(cipher, imp.Bytes)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to create key")
		return
	}
	hmac, err := crypto.GenerateHMACKey(crypto.SHA256, rand.Reader)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to create key")
		return
	}
	if err = s.state.Load().Keys.Create(req.Context(), req.Resource, crypto.KeyVersion{
		Key:       key,
		HMACKey:   hmac,
		CreatedAt: time.Now().UTC(),
		CreatedBy: req.Identity,
	}); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to create key")
		return
	}

	const StatusOK = http.StatusOK
	s.state.Load().Audit.Log(
		fmt.Sprintf("secret key '%s' created", req.Resource),
		StatusOK,
		req,
	)
	resp.Reply(StatusOK)
}

func (s *Server) describeKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	key, err := s.state.Load().Keys.Get(req.Context(), req.Resource)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to read key")
		return
	}

	api.ReplyWith(resp, http.StatusOK, api.DescribeKeyResponse{
		Name:      req.Resource,
		Algorithm: key.Key.Type().String(),
		CreatedAt: key.CreatedAt,
		CreatedBy: key.CreatedBy.String(),
	})
}

func (s *Server) listKeys(resp *api.Response, req *api.Request) {
	if !validPattern(req.Resource) {
		resp.Failf(http.StatusBadRequest, "listing pattern '%s' is empty, too long or is invalid", req.Resource)
		return
	}

	prefix := req.Resource
	if prefix == "*" {
		prefix = ""
	}

	names, prefix, err := s.state.Load().Keys.List(req.Context(), prefix, -1)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to list keys")
	}

	api.ReplyWith(resp, http.StatusOK, api.ListKeysResponse{
		Names:      names,
		ContinueAt: prefix,
	})
}

func (s *Server) deleteKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	if err := s.state.Load().Keys.Delete(req.Context(), req.Resource); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to delete key")
		return
	}

	const StatusOK = http.StatusOK
	s.state.Load().Audit.Log(
		fmt.Sprintf("secret key '%s' deleted", req.Resource),
		StatusOK,
		req,
	)
	resp.Reply(http.StatusOK)
}

func (s *Server) encryptKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var enc api.EncryptKeyRequest
	if err := api.ReadBody(req, &enc); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadRequest, "invalid request body")
		return
	}

	key, err := s.state.Load().Keys.Get(req.Context(), req.Resource)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to read key")
		return
	}
	ciphertext, err := key.Key.Encrypt(enc.Plaintext, enc.Context)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to encrypt plaintext")
		return
	}

	api.ReplyWith(resp, http.StatusOK, api.EncryptKeyResponse{
		Ciphertext: ciphertext,
	})
}

func (s *Server) generateKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var gen api.GenerateKeyRequest
	if req.ContentLength > 0 {
		if err := api.ReadBody(req, &gen); err != nil {
			if err, ok := api.IsError(err); ok {
				resp.Failr(err)
				return
			}

			s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
			resp.Fail(http.StatusBadRequest, "invalid request body")
			return
		}
	}

	key, err := s.state.Load().Keys.Get(req.Context(), req.Resource)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to read key")
		return
	}

	dataKey := make([]byte, 32)
	if _, err = rand.Read(dataKey); err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to generate encryption key")
		return
	}
	ciphertext, err := key.Key.Encrypt(dataKey, gen.Context)
	if err != nil {
		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to generate encryption key")
		return
	}

	api.ReplyWith(resp, http.StatusOK, api.GenerateKeyResponse{
		Plaintext:  dataKey,
		Ciphertext: ciphertext,
	})
}

func (s *Server) decryptKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var enc api.DecryptKeyRequest
	if err := api.ReadBody(req, &enc); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadRequest, "invalid request body")
		return
	}

	key, err := s.state.Load().Keys.Get(req.Context(), req.Resource)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to read key")
		return
	}
	plaintext, err := key.Key.Decrypt(enc.Ciphertext, enc.Context)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusInternalServerError, "failed to decrypt ciphertext")
		return
	}

	api.ReplyWith(resp, http.StatusOK, api.DecryptKeyResponse{
		Plaintext: plaintext,
	})
}

func (s *Server) hmacKey(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "key name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	var body api.HMACRequest
	if err := api.ReadBody(req, &body); err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadRequest, "invalid request body")
		return
	}

	key, err := s.state.Load().Keys.Get(req.Context(), req.Resource)
	if err != nil {
		if err, ok := api.IsError(err); ok {
			resp.Failr(err)
			return
		}

		s.state.Load().Log.ErrorContext(req.Context(), err.Error(), "req", req)
		resp.Fail(http.StatusBadGateway, "failed to read key")
		return
	}
	if !key.HasHMACKey() {
		resp.Fail(http.StatusConflict, "key does not support HMAC")
		return
	}

	api.ReplyWith(resp, http.StatusOK, api.HMACResponse{
		Sum: key.HMACKey.Sum(body.Message),
	})
}

func (s *Server) describePolicy(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "policy name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	state := s.state.Load()
	if _, ok := state.Policies[req.Resource]; !ok {
		resp.Failr(kes.ErrPolicyNotFound)
		return
	}
	api.ReplyWith(resp, http.StatusOK, api.DescribePolicyResponse{
		Name:      req.Resource,
		CreatedAt: state.StartTime,
		CreatedBy: state.Admin.String(),
	})
}

func (s *Server) readPolicy(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "policy name '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	state := s.state.Load()
	policy, ok := state.Policies[req.Resource]
	if !ok {
		resp.Failr(kes.ErrPolicyNotFound)
		return
	}

	allow := make(map[string]struct{}, len(policy.Allow))
	for p := range policy.Allow {
		allow[p] = struct{}{}
	}
	deny := make(map[string]struct{}, len(policy.Deny))
	for p := range policy.Deny {
		deny[p] = struct{}{}
	}

	api.ReplyWith(resp, http.StatusOK, api.ReadPolicyResponse{
		Name:      req.Resource,
		Allow:     allow,
		Deny:      deny,
		CreatedAt: state.StartTime,
		CreatedBy: state.Admin.String(),
	})
}

func (s *Server) listPolicies(resp *api.Response, req *api.Request) {
	if !validPattern(req.Resource) {
		resp.Failf(http.StatusBadRequest, "listing pattern '%s' is empty, too long or is invalid", req.Resource)
		return
	}

	policies := s.state.Load().Policies
	var names []string
	if req.Resource == "" || req.Resource == "*" { // fast path
		names = make([]string, 0, len(policies))
		for name := range policies {
			names = append(names, name)
		}
	} else {
		prefix := req.Resource
		if prefix[len(prefix)-1] == '*' {
			prefix = prefix[:len(prefix)-1]
		}

		names = make([]string, 0, 1+len(policies)/10) // pre-alloc space for ~10%
		for name := range policies {
			if strings.HasPrefix(name, prefix) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)

	api.ReplyWith(resp, http.StatusOK, api.ListPoliciesResponse{
		Names: names,
	})
}

func (s *Server) describeIdentity(resp *api.Response, req *api.Request) {
	if !validName(req.Resource) {
		resp.Failf(http.StatusBadRequest, "identity '%s' is empty, too long or contains invalid characters", req.Resource)
		return
	}

	state := s.state.Load()
	identity := kes.Identity(req.Resource)
	if identity == state.Admin {
		api.ReplyWith(resp, http.StatusOK, api.DescribeIdentityResponse{
			IsAdmin:   true,
			CreatedAt: state.StartTime,
		})
		return
	}

	info, ok := state.Identities[kes.Identity(req.Resource)]
	if !ok {
		resp.Failr(kes.ErrIdentityNotFound)
		return
	}
	api.ReplyWith(resp, http.StatusOK, api.DescribeIdentityResponse{
		Policy:    info.Name,
		CreatedAt: state.StartTime,
		CreatedBy: state.Admin.String(),
	})
}

func (s *Server) listIdentities(resp *api.Response, req *api.Request) {
	if !validPattern(req.Resource) {
		resp.Failf(http.StatusBadRequest, "listing pattern '%s' is empty, too long or is invalid", req.Resource)
		return
	}

	state := s.state.Load()
	var ids []string
	if req.Resource == "" || req.Resource == "*" { // fast path
		ids = make([]string, 0, 1+len(state.Identities))
		ids = append(ids, state.Admin.String())
		for id := range state.Identities {
			ids = append(ids, id.String())
		}
	} else {
		prefix := req.Resource
		if prefix[len(prefix)-1] == '*' {
			prefix = prefix[:len(prefix)-1]
		}

		ids = make([]string, 0, 1+len(state.Identities)/10) // pre-alloc space for ~10%
		if strings.HasPrefix(state.Admin.String(), prefix) {
			ids = append(ids, state.Admin.String())
		}
		for id := range state.Identities {
			if strings.HasPrefix(id.String(), prefix) {
				ids = append(ids, id.String())
			}
		}
	}

	slices.Sort(ids)

	api.ReplyWith(resp, http.StatusOK, api.ListIdentitiesResponse{
		Identities: ids,
	})
}

func (s *Server) selfDescribeIdentity(resp *api.Response, req *api.Request) {
	state := s.state.Load()
	if req.Identity == state.Admin {
		api.ReplyWith(resp, http.StatusOK, api.SelfDescribeIdentityResponse{
			Identity:  req.Identity.String(),
			IsAdmin:   true,
			CreatedAt: state.StartTime,
		})
		return
	}

	info, ok := state.Identities[kes.Identity(req.Resource)]
	if !ok {
		resp.Failr(kes.ErrIdentityNotFound)
		return
	}

	allow := make(map[string]struct{}, len(info.Allow))
	for p := range info.Allow {
		allow[p] = struct{}{}
	}
	deny := make(map[string]struct{}, len(info.Deny))
	for p := range info.Deny {
		deny[p] = struct{}{}
	}

	api.ReplyWith(resp, http.StatusOK, api.SelfDescribeIdentityResponse{
		Identity:  req.Identity.String(),
		CreatedAt: state.StartTime,
		CreatedBy: state.Admin.String(),
		Policy: &api.ReadPolicyResponse{
			Name:      info.Name,
			Allow:     allow,
			Deny:      deny,
			CreatedAt: state.StartTime,
			CreatedBy: state.Admin.String(),
		},
	})
}

func (s *Server) logError(resp *api.Response, req *api.Request) {
	resp.Header().Set(headers.ContentType, headers.ContentTypeJSONLines)
	resp.WriteHeader(http.StatusOK)

	w := api.NewLogWriter(resp.ResponseWriter)
	errLog := s.state.Load().LogHandler
	errLog.out.Add(w)
	defer errLog.out.Remove(w)

	<-req.Context().Done()
}

func (s *Server) logAudit(resp *api.Response, req *api.Request) {
	resp.Header().Set(headers.ContentType, headers.ContentTypeJSONLines)
	resp.WriteHeader(http.StatusOK)

	w := https.FlushOnWrite(resp.ResponseWriter)
	auditLog := s.state.Load().Audit
	auditLog.out.Add(w)
	defer auditLog.out.Remove(w)

	<-req.Context().Done()
}
