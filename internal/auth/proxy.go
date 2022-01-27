// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"sync"

	"github.com/minio/kes"
)

type TLSProxy struct {
	// Identify computes the identity from a X.509 certificate
	// sent by the client or proxy.
	//
	// If it is nil a default IdentityFunc computing the
	// SHA-256 of the certificate's public key will be used.
	Identify IdentityFunc

	// CertHeader is the HTTP header key used to extract the
	// client certificate forwarded by a TLS proxy. The TLS
	// proxy has to include the certificate of the actual
	// client into the request headers as CertHeader.
	//
	// If the request has been sent by a proxy but the request
	// headers do not contain an escaped and ASN.1 encoded
	// certificate then the request will be rejected.
	CertHeader string

	// The X.509 certificate verification options used when
	// verifying the certificate that has been sent by the
	// actual kes client and forwarded by the TLS proxy as
	// part of the request headers.
	//
	// If it is nil the client certificate won't be verified.
	VerifyOptions *x509.VerifyOptions

	lock       sync.RWMutex
	identities map[kes.Identity]bool
}

// Is returns true if and only if the given identity
// is a TLS proxy.
func (p *TLSProxy) Is(identity kes.Identity) bool {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.identities == nil {
		return false
	}
	return p.identities[identity]
}

// Add adds the given identity to the list of TLS
// proxies if:
//  identity != kes.IdentityUnknown
func (p *TLSProxy) Add(identity kes.Identity) {
	if identity.IsUnknown() {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.identities == nil {
		p.identities = map[kes.Identity]bool{}
	}
	p.identities[identity] = true
}

// Verify verifies the given HTTP request. If the request
// has been made by a TLS proxy then Verify tries to extract
// the certificate of the actual kes client from the request
// headers and replaces the peer certificate of the TLS proxy
// with the extracted client certificate.
//
// It verifies the certificate of the actual kes client, if
// present, only if the TLSProxy.VerifyOptions are not nil.
//
// If the request has not been made by a TLS proxy, Verify
// only checks whether a client certificate is present.
func (p *TLSProxy) Verify(req *http.Request) error {
	if req.TLS == nil {
		// This can only happen if the server accepts non-TLS
		// connections - which violates our fundamental security
		// assumption. Therefore, we respond with BadRequest
		// and log that the server is not correctly configured.
		//
		// Technically, it would be acceptable to allow non-TLS
		// connections if:
		// - The kes server and TLS proxy run on the same host
		//   or within the same trusted (!) network (segment).
		// - And, the kes server is ONLY reachable from the TLS
		//   proxy.
		// However, that would be a very fragile setup and there
		// is no real disadvantage caused by using TLS between the
		// proxy and the kes server. Therefore, we fail the request.
		return kes.NewError(http.StatusBadRequest, "insecure connection: TLS required")
	}

	// A TLS proxy may send none, one or multiple peer certificates
	// as part of the TLS handshake. However, we expect exactly
	// one client certificate to check whether it is an authentic
	// proxy that can forward client certificates.
	//
	// In particular, a TLS proxy may send multiple certificates - for
	// example their client certificate as well as intermediate or
	// root CA certificates.
	// Therefore, we filter all CA certificates and only
	// process the remaining leaf certificate(s).
	peerCertificates := make([]*x509.Certificate, 0, len(req.TLS.PeerCertificates))
	for _, cert := range req.TLS.PeerCertificates {
		if cert.IsCA {
			continue
		}
		peerCertificates = append(peerCertificates, cert)
	}

	if len(peerCertificates) == 0 {
		return kes.NewError(http.StatusBadRequest, "no client certificate is present")
	}
	if len(peerCertificates) > 1 {
		return kes.NewError(http.StatusBadRequest, "too many client certificates are present")
	}
	req.TLS.PeerCertificates = peerCertificates

	identity := Identify(req, p.Identify)
	if identity.IsUnknown() {
		return kes.ErrNotAllowed
	}

	// If identity is the/a proxy we extract the certificate
	// of the actual KES client from the request headers and
	// modify the TLS connection state such that for handlers
	// further down the stack it looks like the request has
	// been made by the KES client itself.
	// They can consume the TLS connection state as usual without
	// having to care about a TLS proxy.
	if p.Is(identity) {
		cert, err := p.getClientCertificate(req.Header)
		if err != nil {
			return err
		}

		req.TLS.PeerCertificates = []*x509.Certificate{cert}
		req.TLS.VerifiedChains = nil

		if p.VerifyOptions != nil { // Perform X.509 certificate validation
			opts := *p.VerifyOptions
			req.TLS.VerifiedChains, err = cert.Verify(opts)
			if err != nil {
				// TODO(aead): Decide whether we should return a error
				// message here. For new we can just return 403 forbidden.
				return kes.NewError(http.StatusForbidden, "")
			}
		}
	}
	return nil
}

// getClientCertificate tries to extract an URL-escaped and ANS.1-encoded
// X.509 certificate from the given HTTP headers. It returns an error if
// no or more then one certificate are present or when the certificate
// cannot be decoded.
func (p *TLSProxy) getClientCertificate(h http.Header) (*x509.Certificate, error) {
	clientCerts, ok := h[http.CanonicalHeaderKey(p.CertHeader)]
	if !ok {
		return nil, kes.NewError(http.StatusBadRequest, "no client certificate is present")
	}
	if len(clientCerts) != 1 {
		if len(clientCerts) == 0 {
			return nil, kes.NewError(http.StatusBadRequest, "no client certificate is present")
		}
		return nil, kes.NewError(http.StatusBadRequest, "too many client certificates are present")
	}

	clientCert, err := url.QueryUnescape(clientCerts[0])
	if err != nil {
		return nil, kes.NewError(http.StatusBadRequest, "invalid client certificate")
	}

	block, _ := pem.Decode([]byte(clientCert))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, kes.NewError(http.StatusBadRequest, "invalid client certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, kes.NewError(http.StatusBadRequest, "invalid client certificate")
	}
	return cert, nil
}
