// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package kestest provides utilities for end-to-end
// KES testing.
package kestest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http/httptest"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
)

// NewServer starts and returns a new Server.
// The caller should call Close when finished,
// to shut it down.
func NewServer() *Server {
	s := &Server{}
	s.start()
	return s
}

// A Server is a KES server listening on a system-chosen
// port on the local loopback interface, for use in
// end-to-end tests.
type Server struct {
	URL string // URL is the base URL of the form https://ipaddr:port.

	policies *PolicySet
	client   *kes.Client

	caPrivateKey  crypto.PrivateKey
	caCertificate *x509.Certificate

	server *httptest.Server
}

// Client returns a KES client configured for making requests
// to the server as admin identity.
//
// It is configured to trust the server's TLS test certificate.
func (s *Server) Client() *kes.Client { return s.client }

// Policy returns the PolicySet that contains all KES policies
// and identity-policy associations.
func (s *Server) Policy() *PolicySet { return s.policies }

// Close shuts down the server and blocks until all outstanding
// requests on this server have completed.
func (s *Server) Close() { s.server.Close() }

// IssueClientCertificate returns a new TLS certificate for
// client authentication with the given common name.
//
// The returned certificate is issued by a testing CA that is
// trusted by the Server.
func (s *Server) IssueClientCertificate(name string) tls.Certificate {
	if s.caCertificate == nil || s.caPrivateKey == nil {
		s.caPrivateKey, s.caCertificate = newCA()
	}
	return issueCertificate(name, s.caCertificate, s.caPrivateKey, x509.ExtKeyUsageClientAuth)
}

// CAs returns the Server's root CAs.
func (s *Server) CAs() *x509.CertPool {
	if s.caCertificate == nil || s.caPrivateKey == nil {
		s.caPrivateKey, s.caCertificate = newCA()
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(s.caCertificate)
	return certpool
}

func (s *Server) start() {
	if s.caPrivateKey == nil || s.caCertificate == nil {
		s.caPrivateKey, s.caCertificate = newCA()
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(s.caCertificate)

	var (
		auditLog  = log.NewTarget(io.Discard)
		errorLog  = log.NewTarget(io.Discard)
		metrics   = metric.New()
		adminCert = s.IssueClientCertificate("kestest: admin")
	)
	s.policies = &PolicySet{
		admin:      Identify(&adminCert),
		policies:   make(map[string]*auth.Policy),
		identities: make(map[kes.Identity]auth.IdentityInfo),
	}

	errorLog.Add(metrics.ErrorEventCounter())
	auditLog.Add(metrics.AuditEventCounter())
	store := key.NewCache(&mem.Store{}, &key.CacheConfig{
		Expiry:       30 * time.Second,
		ExpiryUnused: 5 * time.Second,
	})

	serverCert := issueCertificate("kestest: server", s.caCertificate, s.caPrivateKey, x509.ExtKeyUsageServerAuth)
	s.server = httptest.NewUnstartedServer(xhttp.NewServerMux(&xhttp.ServerConfig{
		Version:  "v0.0.0-dev",
		Vault:    sys.NewStatelessVault(Identify(&adminCert), store, s.policies.policySet(), s.policies.identitySet()),
		Proxy:    nil,
		AuditLog: auditLog,
		ErrorLog: errorLog,
		Metrics:  metrics,
	}))
	s.server.TLS = &tls.Config{
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	s.server.StartTLS()
	s.URL = s.server.URL

	s.client = kes.NewClientWithConfig(s.URL, &tls.Config{
		Certificates: []tls.Certificate{adminCert},
		RootCAs:      rootCAs,
	})
}

func newCA() (crypto.PrivateKey, *x509.Certificate) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate CA private key: %v", err))
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate CA certificate serial number: %v", err))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "kestest Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate CA certificate: %v", err))
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate CA certificate: %v", err))
	}
	return privateKey, certificate
}

func issueCertificate(name string, caCert *x509.Certificate, caKey crypto.PrivateKey, extKeyUsage ...x509.ExtKeyUsage) tls.Certificate {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate private/public key pair: %v", err))
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to generate certificate serial number: %v", err))
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	rawCertificate, err := x509.CreateCertificate(rand.Reader, &template, caCert, publicKey, caKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to create certificate: %v", err))
	}
	rawPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to create certificate: %v", err))
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rawCertificate,
	}), pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rawPrivateKey,
	}))
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to create certificate: %v", err))
	}
	return certificate
}
