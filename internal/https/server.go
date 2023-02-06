// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/log"
)

// Config is a structure containing configuration
// fields for an HTTPS server.
type Config struct {
	// Addr specifies an optional TCP address for the
	// server to listen on in the form "host:port".
	// If empty, ":https" (port 443) is used.
	//
	// The service names are defined in RFC 6335 and assigned by IANA.
	// See net.Dial for details of the address format.
	Addr string

	// Handler handles incoming requests.
	Handler http.Handler

	// TLSConfig provides the TLS configuration.
	TLSConfig *tls.Config
}

// NewServer returns a new HTTPS server from
// the given config.
func NewServer(config *Config) *Server {
	srv := &Server{
		addr:      config.Addr,
		tlsConfig: config.TLSConfig,
	}

	srv.handler = &muxHandler{
		lock:    srv.lock.RLocker(),
		Handler: config.Handler,
	}
	return srv
}

// Server is a HTTPS server.
type Server struct {
	addr      string
	handler   *muxHandler
	tlsConfig *tls.Config

	lock sync.RWMutex
}

// Update updates the Server's configuration or
// returns a non-nil error explaining why the
// server configuration couldn't be updated.
func (s *Server) Update(config *Config) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if config.Addr != s.addr {
		return fmt.Errorf("https: failed to update server: '%s' does match existing server address", config.Addr)
	}

	s.tlsConfig = config.TLSConfig.Clone()
	s.handler.Handler = config.Handler
	if s.handler.Handler == nil {
		s.handler.Handler = http.NewServeMux()
	}
	return nil
}

// UpdateTLS updates the Server's TLS configuration
// or returns a non-nil error explaining why the
// server configuration couldn't be updated.
func (s *Server) UpdateTLS(config *tls.Config) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.tlsConfig = config.Clone()
	return nil
}

// Start starts the HTTPS server by listening on the
// Server's address.
//
// If the server address is empty, ":https" is used.
//
// Start blocks until the given ctx.Done() channel returns.
// It always returns a non-nil error. Once ctx.Done()
// returns, the Server gets closed and, if gracefully
// shutdown, Start returns http.ErrServerClosed.
func (s *Server) Start(ctx context.Context) error {
	addr := s.addr
	if addr == "" {
		addr = ":https"
	}
	listener, err := tls.Listen("tcp", addr, &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),

		NextProtos: []string{"h2", "http/1.1"}, // Prefer HTTP/2 but also support HTTP/1.1
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.lock.RLock()
			defer s.lock.RUnlock()
			return s.tlsConfig, nil
		},
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - see timeout handler.
		IdleTimeout:       90 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          log.Default().Log(),
	}
	srvCh := make(chan error, 1)
	go func() { srvCh <- srv.Serve(listener) }()

	select {
	case err := <-srvCh:
		return err
	case <-ctx.Done():
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

type muxHandler struct {
	lock sync.Locker
	http.Handler
}

func (m *muxHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.lock.Lock()
	handler := m.Handler
	m.lock.Unlock()

	handler.ServeHTTP(w, req)
}
