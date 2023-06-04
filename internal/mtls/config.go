// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// Option is a option type for configuring a tls.Config.
type Option func(*tls.Config) error

// WithServerCertificate returns an Option that loads a TLS certificate from the
// certificate and private key files, and adds it to the list of certificates of
// a tls.Config.
//
// An optional password may be specified to decrypt the private key.
//
// If a host is provided, WithServerCertificate verifies that the certificate is valid
// for the host, using the VerifyHostname method of the certificate leaf.
func WithServerCertificate(certFile, keyFile, password, host string) Option {
	return func(c *tls.Config) error {
		certificate, err := CertificateFromFile(certFile, keyFile, password)
		if err != nil {
			return err
		}
		if certificate.Leaf != nil {
			certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				return err
			}
		}
		if len(certificate.Leaf.DNSNames) == 0 && len(certificate.Leaf.IPAddresses) == 0 {
			// Support for TLS certificates with a subject CN but without any SAN
			// has been removed in Go 1.15. Ref: https://go.dev/doc/go1.15#commonname
			// Therefore, we require at least one SAN for the server certificate.
			return errors.New("tls: invalid server certificate: certificate does not contain any Subject Alternative Name (SAN)")
		}
		if host != "" {
			if err := certificate.Leaf.VerifyHostname(host); err != nil {
				return fmt.Errorf("tls: invalid server certificate: certificate is not valid for '%s': %v", host, err)
			}
		}

		c.Certificates = append(c.Certificates, certificate)
		return nil
	}
}

// WithRootCAs returns an Option that configures the root certificate authorities (CAs)
// on a tls.Config. The list of CAs always contains the system's default root CAs and,
// if caPath is non-empty, all X.509 certificates found within the caPath file or directory.
func WithRootCAs(caPath string) Option {
	return func(c *tls.Config) error {
		if caPath == "" {
			rootCAs, err := x509.SystemCertPool()
			if err != nil {
				return err
			}
			c.RootCAs = rootCAs
			return nil
		}

		rootCAs, err := CertPoolFromFile(caPath)
		if err != nil {
			return err
		}
		c.RootCAs = rootCAs
		return nil
	}
}

// WithClientAuth returns an Option that sets the client authentication type on a
// tls.Config.
func WithClientAuth(authType tls.ClientAuthType) Option {
	return func(c *tls.Config) error {
		c.ClientAuth = authType
		return nil
	}
}
