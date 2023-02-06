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
	"github.com/minio/kes/internal/keystore/mem"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
)

// NewGateway starts and returns a new Gateway.
// The caller should call Close when finished,
// to shut it down.
func NewGateway() *Gateway {
	g := &Gateway{}
	g.start()
	return g
}

// A Gateway is a KES gateway listening on a system-chosen
// port on the local loopback interface, for use in
// end-to-end tests.
type Gateway struct {
	URL string

	policies *PolicySet
	client   *kes.Client

	caPrivateKey  crypto.PrivateKey
	caCertificate *x509.Certificate

	server *httptest.Server
}

// Client returns a KES client configured for making requests
// to the Gateway as admin identity.
//
// It is configured to trust the Gateway's TLS test certificate.
func (g *Gateway) Client() *kes.Client { return g.client }

// Policy returns the PolicySet that contains all KES policies
// and identity-policy associations.
func (g *Gateway) Policy() *PolicySet { return g.policies }

// Close shuts down the Gateway and blocks until all outstanding
// requests on this server have completed.
func (g *Gateway) Close() { g.server.Close() }

// IssueClientCertificate returns a new TLS certificate for
// client authentication with the given common name.
//
// The returned certificate is issued by a testing CA that is
// trusted by the Gateway.
func (g *Gateway) IssueClientCertificate(name string) tls.Certificate {
	if g.caCertificate == nil || g.caPrivateKey == nil {
		g.caPrivateKey, g.caCertificate = newCA()
	}
	return issueCertificate(name, g.caCertificate, g.caPrivateKey, x509.ExtKeyUsageClientAuth)
}

// CAs returns the Gateway's root CAs.
func (g *Gateway) CAs() *x509.CertPool {
	if g.caCertificate == nil || g.caPrivateKey == nil {
		g.caPrivateKey, g.caCertificate = newCA()
	}

	certpool := x509.NewCertPool()
	certpool.AddCert(g.caCertificate)
	return certpool
}

func (g *Gateway) start() {
	var (
		rootCAs   = g.CAs()
		auditLog  = log.New(io.Discard, "", 0)
		errorLog  = log.New(io.Discard, "Error", log.Ldate|log.Ltime)
		metrics   = metric.New()
		adminCert = g.IssueClientCertificate("kestest: admin")
	)
	g.policies = &PolicySet{
		admin:      Identify(&adminCert),
		policies:   make(map[string]*auth.Policy),
		identities: make(map[kes.Identity]auth.IdentityInfo),
	}

	auditLog.Add(metrics.AuditEventCounter())
	errorLog.Add(metrics.ErrorEventCounter())
	store := key.NewCache(key.Store{Conn: &mem.Store{}}, &key.CacheConfig{
		Expiry:       30 * time.Second,
		ExpiryUnused: 5 * time.Second,
	})

	serverCert := issueCertificate("kestest: gateway", g.caCertificate, g.caPrivateKey, x509.ExtKeyUsageServerAuth)
	g.server = httptest.NewUnstartedServer(xhttp.NewGatewayMux(&xhttp.GatewayConfig{
		Keys:       store,
		Policies:   g.policies.policySet(),
		Identities: g.policies.identitySet(),
		Proxy:      nil,
		AuditLog:   auditLog,
		ErrorLog:   errorLog,
		Metrics:    metrics,
	}))
	g.server.TLS = &tls.Config{
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	g.server.StartTLS()
	g.URL = g.server.URL

	g.client = kes.NewClientWithConfig(g.URL, &tls.Config{
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
