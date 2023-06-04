// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/mtls"
)

const (
	EnvServer  = "KES_SERVER"
	EnvAPIKey  = "KES_API_KEY"
	EnvEnclave = "KES_ENCLAVE"

	EnvPrivateKey  = "KES_CLIENT_KEY"
	EnvCertificate = "KES_CLIENT_CERT"
)

func EndpointsFromEnv() ([]string, error) {
	endpoint, ok := os.LookupEnv(EnvServer)
	if !ok {
		endpoint = "127.0.0.1:7373"
	}

	endpoints := strings.Split(strings.TrimSpace(endpoint), ",")
	for i, endpoint := range endpoints {
		endpoint = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(endpoint), "http://"), "https://")
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid server endpoint '%s': %v", endpoint, err)
		}
		endpoints[i] = "https://" + net.JoinHostPort(host, port)
	}
	return endpoints, nil
}

func CertificateFromEnv(readPassword func() ([]byte, error)) (tls.Certificate, error) {
	if apiKey, ok := os.LookupEnv(EnvAPIKey); ok {
		if _, ok = os.LookupEnv(EnvPrivateKey); ok {
			return tls.Certificate{}, fmt.Errorf("conflicting environment variables: unset either '%s' or '%s'", EnvAPIKey, EnvPrivateKey)
		}
		if _, ok = os.LookupEnv(EnvCertificate); ok {
			return tls.Certificate{}, fmt.Errorf("conflicting environment variables: unset either '%s' or '%s'", EnvAPIKey, EnvCertificate)
		}

		key, err := kes.ParseAPIKey(apiKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		return kes.GenerateCertificate(key)
	}

	certPath, ok := os.LookupEnv(EnvCertificate)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("no TLS client certificate. Either set '%s' or '%s'", EnvAPIKey, EnvCertificate)
	}
	if strings.TrimSpace(certPath) == "" {
		return tls.Certificate{}, fmt.Errorf("no TLS client certificate. '%s' is empty", EnvCertificate)
	}
	keyPath, ok := os.LookupEnv(EnvPrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("no TLS client private key. Either set '%s' or '%s'", EnvAPIKey, EnvCertificate)
	}
	if strings.TrimSpace(keyPath) == "" {
		return tls.Certificate{}, fmt.Errorf("no TLS client private key. '%s' is empty", EnvCertificate)
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS certificate: %v", err)
	}
	certPem, err = mtls.FilterPEM(certPem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load TLS private key: %v", err)
	}
	privateKey, err := decodePrivateKey(keyPem)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read TLS private key: %v", err)
	}

	if len(privateKey.Headers) > 0 && x509.IsEncryptedPEMBlock(privateKey) {
		password, err := readPassword()
		if err != nil {
			return tls.Certificate{}, err
		}
		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, password)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to decrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}
	return tls.X509KeyPair(certPem, keyPem)
}

func decodePrivateKey(pemBlock []byte) (*pem.Block, error) {
	ErrNoPrivateKey := errors.New("no PEM-encoded private key found")

	for len(pemBlock) > 0 {
		next, rest := pem.Decode(pemBlock)
		if next == nil {
			return nil, ErrNoPrivateKey
		}
		if next.Type == "PRIVATE KEY" || strings.HasSuffix(next.Type, " PRIVATE KEY") {
			return next, nil
		}
		pemBlock = rest
	}
	return nil, ErrNoPrivateKey
}
