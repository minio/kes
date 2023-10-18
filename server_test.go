// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/minio/kes-go"
)

// Self-signed, valid from Oct. 10 2023 until Oct 10 2050
const (
	srvCertificate = `-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIQVBb0Y6QgG4y/Uhsqr15ixDAKBggqhkjOPQQDAjAUMRIw
EAYDVQQDEwlsb2NhbGhvc3QwIBcNMjMxMDEwMDAwMDAwWhgPMjA1MDEwMTAwMDAw
MDBaMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABGSF1/2rUFcQSfd1SY3jBF82BY0MH77fDn7+aR7V8L1M5joDHBqR+TAoqS04
GVIFrMC9vKSYuNVx5Pn0hfQ+Z92jbTBrMA4GA1UdDwEB/wQEAwIChDAdBgNVHSUE
FjAUBggrBgEFBQcDAgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAsBgNVHREEJTAj
gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwCgYIKoZIzj0EAwID
SAAwRQIhAPXQ9LRiCQZJruplDQnrRUt3OJxd9vhZQmmhbWC8zKMPAiB7sy46Fgrg
DB5wr8jkeZpC5Inb1yjbyoHOD6sfQUdm9g==
-----END CERTIFICATE-----`

	srvPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj0xKJXLMx/S9dc5w
dJ9Dm4+lX7qYfHRNGoJiF+DAbtKhRANCAARkhdf9q1BXEEn3dUmN4wRfNgWNDB++
3w5+/mke1fC9TOY6AxwakfkwKKktOBlSBazAvbykmLjVceT59IX0Pmfd
-----END PRIVATE KEY-----`
)

const (
	defaultAPIKey   = "kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc"
	defaultIdentity = "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22"
)

func startServer(ctx context.Context, conf *Config) (*Server, string) {
	ln := newLocalListener()

	if conf == nil {
		conf = &Config{}
	}
	if conf.Admin == "" {
		conf.Admin = defaultIdentity
	}
	if conf.TLS == nil {
		conf.TLS = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequestClientCert,
			Certificates: []tls.Certificate{defaultServerCertificate()},
			NextProtos:   []string{"h2", "http/1.1"},
		}
	}
	if conf.Cache == nil {
		conf.Cache = &CacheConfig{
			Expiry:        5 * time.Minute,
			ExpiryUnused:  30 * time.Second,
			ExpiryOffline: 0,
		}
	}
	if conf.Keys == nil {
		conf.Keys = &MemKeyStore{}
	}
	if conf.ErrorLog == nil {
		conf.ErrorLog = discardLog{}
	}
	if conf.AuditLog == nil {
		conf.AuditLog = discardAudit{}
	}

	srv := &Server{
		ShutdownTimeout: -1, // wait for all requests to finish
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		if err := srv.Start(ctx, ln, conf); err != nil {
			panic(fmt.Sprintf("serve failed: %v", err))
		}
	}()
	wg.Wait()

	for srv.Addr() == "" {
		time.Sleep(5 * time.Microsecond)
	}
	return srv, "https://" + ln.Addr().String()
}

func testContext(t *testing.T) context.Context {
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		t.Cleanup(cancel)
		return ctx

	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func defaultClient(endpoint string) *kes.Client {
	adminKey, err := kes.ParseAPIKey(defaultAPIKey)
	if err != nil {
		panic(fmt.Sprintf("kes: failed to parse API key '%s': %v", defaultAPIKey, err))
	}
	clientCert, err := kes.GenerateCertificate(adminKey)
	if err != nil {
		panic(fmt.Sprintf("kes: failed to generate client certificate: %v", err))
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(defaultServerCertificate().Leaf)

	return kes.NewClientWithConfig(endpoint, &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		},
	})
}

func newLocalListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if l, err = net.Listen("tcp6", "[::1]:0"); err != nil {
			panic(fmt.Sprintf("kes: failed to listen on a port: %v", err))
		}
	}
	return l
}

func defaultServerCertificate() tls.Certificate {
	cert, err := tls.X509KeyPair([]byte(srvCertificate), []byte(srvPrivateKey))
	if err != nil {
		panic(fmt.Sprintf("kes: failed to parse server certificate: %v", err))
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert
}

type discardLog struct{}

func (discardLog) Enabled(context.Context, slog.Level) bool { return false }

func (discardLog) Handle(context.Context, slog.Record) error { return nil }

func (h discardLog) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h discardLog) WithGroup(string) slog.Handler { return h }

type discardAudit struct{}

func (discardAudit) Enabled(context.Context, slog.Level) bool { return false }

func (discardAudit) Handle(context.Context, AuditRecord) error { return nil }
