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
	"sync"
	"time"

	xlog "github.com/minio/kes/internal/log"
)

// LoadCertificate returns a X.509 TLS certificate from the
// given certificate and private key files.
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

// readCertificate reads the TLS certificate from
// the given file path.
func readCertificate(certFile string) ([]byte, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(data), nil
}

// readPrivateKey reads the TLS private key from the
// given file path.
//
// It decrypts the private key using the given password
// if the private key is an encrypted PEM block.
func readPrivateKey(keyFile, password string) ([]byte, error) {
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	pemBlock, rest := pem.Decode(keyPEMBlock)
	if len(rest) > 0 {
		return nil, errors.New("http: private key contains additional data")
	}

	if !x509.IsEncryptedPEMBlock(pemBlock) {
		return keyPEMBlock, nil
	}
	if password == "" {
		return nil, errors.New("http: private key is encrypted: password required")
	}

	plaintext, err := x509.DecryptPEMBlock(pemBlock, []byte(password))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemBlock.Type, Bytes: plaintext}), nil
}
