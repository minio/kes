// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	mrand "math/rand"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/log"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
)

// ErrStopped is returned by the Server's Start and Update
// methods after a call to Stop.
var ErrStopped = errors.New("kes: server is shutdown")

// Signal represents a server signal sent on certain cluster
// or server events, like stopping a running server.
type Signal uint

const (
	SigStart Signal = iota // Server has been started
	SigStop                // Server has been stopped
	SigJoin                // A server has joined the cluster
	SigLeave               // A server has left the cluster
)

// NewServer returns a new Server with the given address.
func NewServer(addr Addr) *Server {
	return &Server{
		addr: addr,
	}
}

// Server represents a KES server.
//
// A server may be its own single-node cluster or may
// one of the nodes within a multi-node cluster.
type Server struct {
	addr      Addr
	path      string
	startTime time.Time
	mux       mux

	ctx               context.Context
	stop              context.CancelCauseFunc
	starting, started atomic.Bool
	shutdown          atomic.Bool

	mu        sync.RWMutex
	db        *bolt.DB
	cluster   cluster
	hsm       HSM
	admin     kes.Identity
	apiKey    kes.APIKey
	rootKey   crypto.SecretKey
	routes    map[string]api.API
	client    *http.Client
	tlsConfig atomic.Pointer[tls.Config]

	commit            commit
	id, leaderID      int
	state             atomic.Uint32
	eventReplicated   atomic.Bool
	heartbeatReceived atomic.Bool

	heartbeatInterval time.Duration
	electionTimeout   time.Duration
	heartbeatTicker   *time.Ticker
	electionTicker    *time.Ticker

	signals  chan Signal
	sigMu    sync.RWMutex
	onSignal map[Signal][]func()
}

// State returns a snapshot of the current server state.
// If the server hasn't been started, an empty State is
// returned.
func (s *Server) State() State {
	if !s.started.Load() {
		return State{}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	return State{
		Addr:              s.addr,
		ID:                s.id,
		Admin:             s.admin,
		APIKey:            s.apiKey,
		LeaderID:          s.leaderID,
		State:             s.state.Load(),
		Commit:            s.commit.N,
		Cluster:           maps.Clone(s.cluster),
		HeartbeatInterval: s.heartbeatInterval,
		ElectionTimeout:   s.electionTimeout,
	}
}

// Register registers a signal handler f that gets invoked whenever
// sig is received. Handlers should not perform long-running or
// expensive operations.
//
// A common usage of Register is to get notified by the SigStart
// signal once the server has been started.
func (s *Server) Register(sig Signal, f func()) {
	if sig > SigLeave { // Update when adding new signals
		return
	}

	s.sigMu.Lock()
	defer s.sigMu.Unlock()

	if s.onSignal == nil {
		s.onSignal = map[Signal][]func(){}
	}
	s.onSignal[sig] = append(s.onSignal[sig], f)
}

func (n *Server) Update(ctx context.Context, config *Config) error {
	if n.shutdown.Load() {
		return ErrStopped
	}
	if !n.started.Load() {
		return errors.New("kes: server not started")
	}

	if config == nil || config.HSM == nil {
		return errors.New("kes: invalid config: no HSM specified")
	}
	if config.TLS == nil || (len(config.TLS.Certificates) == 0 && config.TLS.GetCertificate == nil && config.TLS.GetConfigForClient == nil) {
		return errors.New("kes: invalid config: no server certificate specified")
	}

	apiKey, cert, err := generateAPIKey(ctx, config.HSM, nil)
	if err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	cluster, id, err := initCluster(filepath.Join(n.path, fsClusterFile), n.addr)
	if err != nil {
		return err
	}
	rootKey, commit, err := initState(ctx, n.db, config.HSM)
	if err != nil {
		return err
	}
	mux, routes := initRoutes(n)

	n.apiKey = apiKey
	n.hsm = config.HSM
	n.cluster = cluster
	n.id = id
	n.rootKey = rootKey
	n.commit = commit
	n.routes = routes

	n.tlsConfig.Store(config.TLS.Clone())
	n.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      config.TLS.RootCAs,

				MinVersion:       tls.VersionTLS12,
				CipherSuites:     fips.TLSCiphers(),
				CurvePreferences: fips.TLSCurveIDs(),
			},
		},
	}

	n.heartbeatInterval, n.electionTimeout = configureTimeouts(config.HeartbeatInterval, config.ElectionTimeout)
	n.heartbeatTicker.Reset(n.heartbeatInterval)
	n.electionTicker.Reset(n.electionTimeout)

	n.mux.Swap(mux)
	return nil
}

func (n *Server) Start(ctx context.Context, path string, config *Config) error {
	if n.shutdown.Load() {
		return ErrStopped
	}
	if !n.starting.CompareAndSwap(false, true) {
		return errors.New("kes: server already started")
	}

	if config == nil || config.HSM == nil {
		return errors.New("kes: invalid config: no HSM specified")
	}
	if config.TLS == nil || (len(config.TLS.Certificates) == 0 && config.TLS.GetCertificate == nil && config.TLS.GetConfigForClient == nil) {
		return errors.New("kes: invalid config: no server certificate specified")
	}

	addr := ":https"
	if config != nil && config.Addr != "" {
		addr = config.Addr
	}

	db, err := bolt.Open(filepath.Join(path, fsDBFile), 0o640, &bolt.Options{
		Timeout:      3 * time.Second,
		FreelistType: bolt.FreelistMapType,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),

		NextProtos:         []string{"h2", "http/1.1"}, // Prefer HTTP/2 but also support HTTP/1.1
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return n.tlsConfig.Load(), nil },
	})
	if err != nil {
		return err
	}
	defer listener.Close()

	apiKey, cert, err := generateAPIKey(ctx, config.HSM, nil)
	if err != nil {
		return err
	}
	cluster, id, err := initCluster(filepath.Join(path, fsClusterFile), n.addr)
	if err != nil {
		return err
	}
	rootKey, commit, err := initState(ctx, db, config.HSM)
	if err != nil {
		return err
	}
	mux, routes := initRoutes(n)

	// We have to hold the lock since a concurrent call to e.g. State
	// could see partial information. However, this lock does not serialize
	// concurrent calls to Start. This is already done by starting.CompareAndSwap.
	n.mu.Lock()

	n.path = path
	n.db = db
	n.ctx, n.stop = context.WithCancelCause(ctx)
	n.startTime = time.Now()

	n.apiKey = apiKey
	n.hsm = config.HSM
	n.cluster = cluster
	n.rootKey = rootKey
	n.routes = routes

	n.commit = commit
	n.id, n.leaderID = id, -1
	n.state.Store(Follower)

	n.tlsConfig.Store(config.TLS.Clone())
	n.client = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				RootCAs:      config.TLS.RootCAs,

				MinVersion:       tls.VersionTLS12,
				CipherSuites:     fips.TLSCiphers(),
				CurvePreferences: fips.TLSCurveIDs(),
			},
		},
	}

	n.heartbeatInterval, n.electionTimeout = configureTimeouts(config.HeartbeatInterval, config.ElectionTimeout)
	n.heartbeatTicker = time.NewTicker(n.heartbeatInterval)
	n.electionTicker = time.NewTicker(n.electionTimeout)
	defer n.heartbeatTicker.Stop()
	defer n.electionTicker.Stop()

	n.signals = make(chan Signal, 1)
	n.mu.Unlock()

	n.mux.Store(mux)
	srv := &http.Server{
		Handler:           &n.mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - we use http.ResponseController
		IdleTimeout:       90 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return n.ctx },
		// ErrorLog:          log.New(io.Discard, "", 0).Log(), // log.Default().Log(),
		ErrorLog: log.Default().Log(),
	}
	srvCh := make(chan error, 1)
	go func() { srvCh <- srv.Serve(listener) }()
	go n.notifyOnSignal()
	go n.startHeartbeats()

	n.started.Store(true)
	notify(n.signals, SigStart)

	select {
	case err := <-srvCh:
		return err
	case <-n.ctx.Done():
		n.shutdown.Store(true)
		notify(n.signals, SigStop)

		graceCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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

// Stop stops a started server. Once stopped,
// a server cannot be started again and Start
// returns ErrStopped.
//
// If the server is already stopped or has been
// shutdown in any other way, Stop does nothing.
func (s *Server) Stop() {
	if s.shutdown.CompareAndSwap(false, true) {
		s.stop(context.Canceled)
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

func (s *Server) startHeartbeats() {
	for {
		select {
		case <-s.heartbeatTicker.C:
			if s.state.Load() == Leader {
				s.sendHeartbeats()
			}
		case <-s.electionTicker.C:
			if !s.heartbeatReceived.CompareAndSwap(true, false) {
				s.requestVotes()
			}
		case <-s.ctx.Done():
			s.heartbeatTicker.Stop()
			s.electionTicker.Stop()
			return
		}
	}
}

func (s *Server) sendHeartbeats() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var wg errgroup.Group
	for id, addr := range s.cluster {
		if id == s.id {
			continue
		}
		addr := addr

		wg.Go(func() error {
			return replicate(s.ctx, s.client, addr, api.ReplicateRPCRequest{
				NodeID:      s.id,
				Commit:      s.commit.N,
				CommandType: s.commit.Type,
				Command:     s.commit.Command,
			})
		})
	}
	if err := wg.Wait(); err == nil {
		s.eventReplicated.Store(true)
	}
}

func (s *Server) requestVotes() {
	if !s.state.CompareAndSwap(Follower, Candidate) {
		return
	}
	defer s.state.CompareAndSwap(Candidate, Follower)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.leaderID = -1
	wg, ctx := errgroup.WithContext(s.ctx)
	for id, addr := range s.cluster {
		if id == s.id {
			continue
		}
		addr := addr

		wg.Go(func() error {
			return requestVote(ctx, s.client, addr, api.VoteRPCRequest{
				NodeID: s.id,
				Commit: s.commit.N,
			})
		})
	}
	if err := wg.Wait(); err != nil {
		return
	}

	s.state.Store(Leader)
	s.leaderID = s.id
	s.heartbeatReceived.Store(true)
	s.eventReplicated.Store(false)
}

type mux struct {
	atomic.Pointer[http.ServeMux]
}

func (m *mux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Load().ServeHTTP(w, r)
}

func generateAPIKey(ctx context.Context, hsm HSM, seed []byte) (kes.APIKey, tls.Certificate, error) {
	apiKey, err := hsm.APIKey(ctx, seed)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, err := kes.GenerateCertificate(apiKey, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(5 * 24 * 365 * time.Hour)
	})
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	return apiKey, cert, nil
}

func configureTimeouts(heartbeatInterval, electionTimeout time.Duration) (time.Duration, time.Duration) {
	if heartbeatInterval <= 0 {
		heartbeatInterval = DefaultHeartbeatInterval
	}
	if electionTimeout <= 0 {
		electionTimeout = DefaultElectionTimeout
	}
	if electionTimeout < 2*heartbeatInterval {
		electionTimeout = 2 * heartbeatInterval
	}

	electionTimeout += time.Duration(mrand.Int63n(int64(heartbeatInterval) / 2))
	return heartbeatInterval, electionTimeout
}

// notify tries to send v over the channel ch and
// reports whether v has been sent.
//
// If the channel is currently blocked, e.g. due
// to slow receivers, it drops v.
func notify[T any](ch chan<- T, v T) bool {
	select {
	case ch <- v:
		return true
	default:
		return false
	}
}
