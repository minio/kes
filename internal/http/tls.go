// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	xlog "github.com/minio/kes/internal/log"
)

// LoadCertificate returns a X.509 TLS certificate from the
// given certificate and private key files.
func LoadCertificate(certFile, keyFile string) (*Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
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
	}, nil
}

// Certificate is a X.509 TLS certificate.
type Certificate struct {
	ErrorLog *xlog.Target

	lock        sync.RWMutex
	certificate tls.Certificate

	certFile, keyFile string
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

		newCert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			if c.ErrorLog != nil && (lastReloadErr == nil || err.Error() != lastReloadErr.Error()) {
				c.ErrorLog.Log().Printf("http: failed to reload certificate %q", c.certFile)
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
