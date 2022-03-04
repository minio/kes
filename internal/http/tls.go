// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	xlog "github.com/minio/kes/internal/log"
)

// LoadCertificate returns a new Certificate from the
// given certificate and private key files.
//
// The password is used to decrypt the private key if
// it is encrypted.
func LoadCertificate(certFile, keyFile, password string) (*Certificate, error) {
	certBytes, err := readCertificate(certFile)
	if err != nil {
		return nil, err
	}
	keyBytes, err := readPrivateKey(keyFile, password)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, err
	}
	if certificate.Leaf == nil {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	return &Certificate{
		certificate: certificate,
		certFile:    certFile,
		keyFile:     keyFile,
		password:    password,
	}, nil
}

// NewCertificate returns a new Certificate from the
// given TLS certificate.
func NewCertificate(cert tls.Certificate) *Certificate {
	return &Certificate{
		certificate: cert,
	}
}

// Certificate is a X.509 TLS certificate.
type Certificate struct {
	ErrorLog *xlog.Target

	lock        sync.RWMutex
	certificate tls.Certificate

	certFile, keyFile string
	password          string
}

// GetCertificate returns a X.509 TLS certificate
// based on the TLS client hello.
func (c *Certificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return &c.certificate, nil
}

// ReloadAfter reloads the X.509 TLS certificate from its
// certificate resp. private key file periodically in an
// infinite loop.
//
// Once the ctx.Done() channel returns ReloadAfter exits.
func (c *Certificate) ReloadAfter(ctx context.Context, interval time.Duration) {
	if c.certFile == "" || c.keyFile == "" {
		return
	}

	var lastReloadErr error
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		certBytes, err := readCertificate(c.certFile)
		if err != nil {
			if c.ErrorLog != nil && (lastReloadErr == nil || err.Error() != lastReloadErr.Error()) {
				c.ErrorLog.Log().Printf("http: failed to reload certificate %q: %v", c.certFile, err)
				lastReloadErr = err
			}
			continue
		}
		keyBytes, err := readPrivateKey(c.keyFile, c.password)
		if err != nil {
			if c.ErrorLog != nil && (lastReloadErr == nil || err.Error() != lastReloadErr.Error()) {
				c.ErrorLog.Log().Printf("http: failed to reload private key %q: %v", c.keyFile, err)
				lastReloadErr = err
			}
			continue
		}
		newCert, err := tls.X509KeyPair(certBytes, keyBytes)
		if err != nil {
			if c.ErrorLog != nil && (lastReloadErr == nil || err.Error() != lastReloadErr.Error()) {
				c.ErrorLog.Log().Printf("http: failed to reload certificate %q: %v", c.certFile, err)
				lastReloadErr = err
			}
			continue
		}

		// We set the certificate leaf to the actual certificate such that
		// we don't have to do the parsing (multiple times) when matching the
		// certificate to the client hello. This a performance optimisation.
		if newCert.Leaf == nil {
			newCert.Leaf, _ = x509.ParseCertificate(newCert.Certificate[0])
		}

		c.lock.Lock()
		c.certificate = newCert
		c.lock.Unlock()
	}
}

// FilterPEM applies the filter function on each PEM block
// in pemBlocks and returns an error if at least one PEM
// block does not pass the filter.
func FilterPEM(pemBlocks []byte, filter func(*pem.Block) bool) ([]byte, error) {
	pemBlocks = bytes.TrimSpace(pemBlocks)

	b := pemBlocks
	for len(b) > 0 {
		next, rest := pem.Decode(b)
		if next == nil {
			return nil, errors.New("http: no valid PEM data")
		}
		if !filter(next) {
			return nil, errors.New("http: unsupported PEM data block")
		}
		b = rest
	}
	return pemBlocks, nil
}

// readCertificate reads the TLS certificate from
// the given file path.
func readCertificate(certFile string) ([]byte, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return FilterPEM(data, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
}

// readPrivateKey reads the TLS private key from the
// given file path.
//
// It decrypts the private key using the given password
// if the private key is an encrypted PEM block.
func readPrivateKey(keyFile, password string) ([]byte, error) {
	pemBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	pemBlock, err = FilterPEM(pemBlock, func(b *pem.Block) bool {
		return b.Type == "CERTIFICATE" || b.Type == "PRIVATE KEY" || strings.HasSuffix(b.Type, " PRIVATE KEY")
	})
	if err != nil {
		return nil, err
	}

	for len(pemBlock) > 0 {
		next, rest := pem.Decode(pemBlock)
		if next == nil {
			return nil, errors.New("http: no PEM-encoded private key found")
		}
		if next.Type != "PRIVATE KEY" && !strings.HasSuffix(next.Type, " PRIVATE KEY") {
			pemBlock = rest
			continue
		}

		if x509.IsEncryptedPEMBlock(next) {
			if password == "" {
				return nil, errors.New("http: private key is encrypted: password required")
			}
			plaintext, err := x509.DecryptPEMBlock(next, []byte(password))
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{Type: next.Type, Bytes: plaintext}), nil
		}
		return pem.EncodeToMemory(next), nil
	}
	return nil, errors.New("http: no PEM-encoded private key found")
}
