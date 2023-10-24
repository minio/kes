// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
)

// verifyIdentity authenticates client requests by verifying that
// the client provides a certificate during the TLS handshake (mTLS)
// and that the identity of the certificate public key matches either
// the admin identity or an identity with an assigned policy.
//
// A request is accepted if the identity matches the admin identity
// or the policy associated to the identity allows the request. The
// later is the case if none of the policy's deny rules and at least
// one of the policy's allow rules apply. Otherwise, the request is
// rejected.
type verifyIdentity atomic.Pointer[serverState]

// Authenticate verifies that the request is either sent by the
// server admin or passes the policy assigned to the identity.
// Otherwise, it returns an error.
func (v *verifyIdentity) Authenticate(req *http.Request) (*api.Request, api.Error) {
	s := (*atomic.Pointer[serverState])(v).Load()
	identity, err := identifyRequest(req.TLS)
	if err != nil {
		s.Log.DebugContext(req.Context(), err.Error(), "req", req)
		return nil, err
	}
	if identity == s.Admin {
		return &api.Request{
			Request:  req,
			Identity: identity,
		}, nil
	}

	policy, ok := s.Identities[identity]
	if !ok {
		s.Log.DebugContext(req.Context(), "access denied: identity not found", "req", req)
		return nil, kes.ErrNotAllowed
	}
	if err := policy.Verify(req); err != nil {
		s.Log.DebugContext(req.Context(), fmt.Sprintf("access denied: rejected by policy '%s'", policy.Name), "req", req)
		return nil, kes.ErrNotAllowed
	}

	return &api.Request{
		Request:  req,
		Identity: identity,
	}, nil
}

// insecureIdentifyOnly does not authenticate client requests but
// computes the certificate public key identity, if provided.
// It does not return an error if the client did not provide a
// certificate, or an invalid one, during the TLS handshake. In
// such a case, the identity of the returned request is empty.
type insecureIdentifyOnly struct{}

func (insecureIdentifyOnly) Authenticate(req *http.Request) (*api.Request, api.Error) {
	identity, _ := identifyRequest(req.TLS)
	return &api.Request{
		Request:  req,
		Identity: identity,
	}, nil
}

func identifyRequest(state *tls.ConnectionState) (kes.Identity, api.Error) {
	if state == nil {
		return "", api.NewError(http.StatusBadRequest, "insecure connection: TLS is required")
	}

	var cert *x509.Certificate
	for _, c := range state.PeerCertificates {
		if c.IsCA {
			continue
		}
		if cert != nil {
			return "", api.NewError(http.StatusBadRequest, "tls: received more than one client certificate")
		}
		cert = c
	}
	if cert == nil {
		return "", api.NewError(http.StatusBadRequest, "tls: client certificate is required")
	}

	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(h[:])), nil
}

// validName reports whether s is a valid {policy|identity|key} name.
//
// Valid names only contain the characters:
//   - 0-9
//   - A-Z
//   - a-z
//   - '-'  (hyphen, must not be first/last character)
//   - '_'  (underscore, must not be the only character)
//
// More characters may be allowed in the future.
func validName(s string) bool {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if s == "" || s == "_" || len(s) > MaxLength {
		return false
	}

	n := len(s) - 1
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-' && i > 0 && i < n:
		case r == '_':
		default:
			return false
		}
	}
	return true
}

// validPattern reports whether s is a valid pattern for
// listing {policy|identity|key} names.
//
// Valid patterns only contain the characters:
//   - 0-9
//   - A-Z
//   - a-z
//   - '-'  (hyphen, must not be first/last character)
//   - '_'  (underscore, must not be the only character)
//   - '*'  (only as last character)
//
// More characters may be allowed in the future.
func validPattern(s string) bool {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if s == "*" { // fast path
		return true
	}
	if s == "_" || len(s) > MaxLength {
		return false
	}

	n := len(s) - 1
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-' && i > 0 && i < n:
		case r == '_':
		case r == '*' && i == n:
		default:
			return false
		}
	}
	return true
}
