// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type Server struct {
	addr      kes.Addr
	startTime time.Time
	metrics   *metric.Metrics
	state     mux

	ctx               context.Context
	stop              context.CancelCauseFunc
	starting, started atomic.Bool
	shutdown          atomic.Bool

	signals  chan kes.Signal
	sigMu    sync.RWMutex
	onSignal map[kes.Signal][]func()
}

// State returns a snapshot of the current Server state.
// If the Server hasn't been started, returns an empty State.
func (s *Server) State() State {
	if !s.started.Load() {
		return State{}
	}

	return State{
		StartTime: s.startTime,
		Addr:      s.addr,
	}
}

func (s *Server) Update(store KeyStore, config *Config) error {
	if s.shutdown.Load() {
		return kes.ErrStopped
	}
	if !s.started.Load() {
		return errors.New("kes: server not started")
	}
	return s.update(store, config)
}

func (s *Server) Start(ctx context.Context, store KeyStore, config *Config) error {
	if s.shutdown.Load() {
		return kes.ErrStopped
	}
	if !s.starting.CompareAndSwap(false, true) {
		return errors.New("edge: server already started")
	}

	addr := config.Addr
	if addr == "" {
		addr = ":https"
	}

	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),

		NextProtos: []string{"h2", "http/1.1"}, // Prefer HTTP/2 but also support HTTP/1.1
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return s.state.Load().TLS, nil
		},
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	s.addr, err = kes.ParseAddr(listener.Addr().String())
	if err != nil {
		return err
	}
	s.ctx, s.stop = context.WithCancelCause(ctx)
	s.startTime = time.Now()
	s.metrics = metric.New()
	s.signals = make(chan kes.Signal, 1)
	if err := s.update(store, config); err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           &s.state,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - we use http.ResponseController
		IdleTimeout:       90 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		// ErrorLog:          log.New(io.Discard, "", 0).Log(), // log.Default().Log(),
		ErrorLog: log.Default().Log(),
	}
	srvCh := make(chan error, 1)
	go func() { srvCh <- srv.Serve(listener) }()
	go s.notifyOnSignal()

	s.started.Store(true)
	trySend(s.signals, kes.SigStart)

	select {
	case err := <-srvCh:
		return err
	case <-ctx.Done():
		s.shutdown.Store(true)
		trySend(s.signals, kes.SigStop)

		if state := s.state.Load(); state != nil && state.Keys != nil {
			state.Keys.Stop()
		}

		graceCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		err := srv.Shutdown(graceCtx)
		if errors.Is(err, context.DeadlineExceeded) {
			err = srv.Close()
		}
		if err == nil {
			err = http.ErrServerClosed
		}
		return err
	}
}

// Register registers a signal handler f that gets invoked whenever
// sig is received. Handlers should not perform long-running or
// expensive operations.
//
// A common usage of Register is to get notified by the SigStart
// signal once the Server has been started.
func (s *Server) Register(sig kes.Signal, f func()) {
	if sig > kes.SigLeave { // Update when adding new signals
		return
	}

	s.sigMu.Lock()
	defer s.sigMu.Unlock()

	if s.onSignal == nil {
		s.onSignal = map[kes.Signal][]func(){}
	}
	s.onSignal[sig] = append(s.onSignal[sig], f)
}

// Stop stops a started Server. Once stopped,
// a Server cannot be started again and Start
// returns kes.ErrStopped.
//
// If the Server is already stopped or has been
// shutdown in any other way, Stop does nothing.
func (s *Server) Stop() {
	if s.shutdown.CompareAndSwap(false, true) {
		s.stop(kes.ErrStopped)
	}
}

func (s *Server) notifyOnSignal() {
	for {
		select {
		case sig := <-s.signals:
			var funcs []func()

			s.sigMu.RLock()
			if f, ok := s.onSignal[sig]; ok {
				funcs = slices.Clone(f)
			}
			s.sigMu.RUnlock()

			for _, f := range funcs {
				f()
			}
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Server) update(store KeyStore, config *Config) error {
	state := &serverState{
		Mux:       http.NewServeMux(),
		Admin:     config.Admin,
		TLS:       config.TLS.Clone(),
		StartTime: s.startTime,
		Metrics:   s.metrics,
	}

	if config.ErrorLog != nil {
		state.ErrorLog = log.New(os.Stderr, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	} else {
		state.ErrorLog = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	}
	if config.AuditLog != nil {
		state.AuditLog = log.New(os.Stdout, "", 0)
	} else {
		state.AuditLog = log.New(io.Discard, "", 0)
	}

	state.Policies = make(map[string]*auth.Policy, len(config.Policies))
	for name, policy := range config.Policies {
		allow := make(map[string]auth.Rule, len(policy.Allow))
		for path := range policy.Allow {
			allow[path] = auth.Rule{}
		}

		deny := make(map[string]auth.Rule, len(policy.Deny))
		for path := range policy.Deny {
			deny[path] = auth.Rule{}
		}

		state.Policies[name] = &auth.Policy{
			Allow:     allow,
			Deny:      deny,
			CreatedAt: s.startTime,
			CreatedBy: config.Admin,
		}
	}
	state.Identities = maps.Clone(config.Identities)

	state.Keys = NewCache(s.ctx, store, &CacheConfig{
		Expiry:        config.Cache.Expiry,
		ExpiryUnused:  config.Cache.ExpiryUnused,
		ExpiryOffline: config.Cache.ExpiryOffline,
	})
	initRoutes(state, config.API)

	if s := s.state.Swap(state); s != nil && s.Keys != nil {
		s.Keys.Stop()
	}
	return nil
}

type mux struct {
	atomic.Pointer[serverState]
}

func (m *mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Load().Mux.ServeHTTP(w, r)
}

// trySend tries to send v over the channel ch and
// reports whether v has been sent.
//
// If the channel is currently blocked, e.g. due
// to slow receivers, it drops v.
func trySend[T any](ch chan<- T, v T) bool {
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}
