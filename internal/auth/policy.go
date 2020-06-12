// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"

	"github.com/minio/kes"
)

// IdentityFunc maps a X.509 certificate to an
// Identity. This mapping should be deterministic
// and unique in the sense that:
//  1. The same certificate always gets mapped to same identity.
//  2. There is only one (valid / non-expired) certificate that
//     gets mapped to a particular (known) identity.
//
// If no certificate is provided or an identity
// cannot be computed - e.g. because the certificate
// does not contain enough information - the IdentityFunc
// should return IdentityUnknown.
type IdentityFunc func(*x509.Certificate) kes.Identity

// HashPublicKey returns an IdentityFunc that
// computes an identity as the cryptographic
// hash of the certificate's public key.
//
// If the hash function is not available
// it uses crypto.SHA256.
func HashPublicKey(hash crypto.Hash) IdentityFunc {
	if !hash.Available() {
		hash = crypto.SHA256
	}
	return func(cert *x509.Certificate) kes.Identity {
		if cert == nil {
			return kes.IdentityUnknown
		}
		h := hash.New()
		h.Write(cert.RawSubjectPublicKeyInfo)
		return kes.Identity(hex.EncodeToString(h.Sum(nil)))
	}
}

type Roles struct {
	Root     kes.Identity
	Identify IdentityFunc

	lock           sync.RWMutex
	roles          map[string]*kes.Policy  // all available roles
	effectiveRoles map[kes.Identity]string // identities for which a mapping to a policy name exists
}

func (r *Roles) Set(name string, policy *kes.Policy) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*kes.Policy{}
	}
	r.roles[name] = policy
}

func (r *Roles) Get(name string) (*kes.Policy, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.roles == nil {
		return nil, false
	}
	policy, ok := r.roles[name]
	return policy, ok
}

func (r *Roles) Delete(name string) {
	r.lock.Lock()
	defer r.lock.Unlock()

	delete(r.roles, name)
	if r.effectiveRoles != nil { // Remove all assigned identities
		for id, policy := range r.effectiveRoles {
			if name == policy {
				delete(r.effectiveRoles, id)
			}
		}
	}
}

func (r *Roles) Policies() (names []string) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	names = make([]string, 0, len(r.roles))
	for name := range r.roles {
		names = append(names, name)
	}
	return
}

func (r *Roles) Assign(name string, id kes.Identity) error {
	if id == r.Root {
		return errors.New("key: identity is root")
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*kes.Policy{}
	}
	_, ok := r.roles[name]
	if !ok {
		return kes.ErrPolicyNotFound
	}
	if r.effectiveRoles == nil {
		r.effectiveRoles = map[kes.Identity]string{}
	}
	r.effectiveRoles[id] = name
	return nil
}

func (r *Roles) IsAssigned(id kes.Identity) bool {
	if id == r.Root {
		return true
	}

	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.effectiveRoles != nil {
		if name, ok := r.effectiveRoles[id]; ok {
			_, ok = r.roles[name]
			return ok
		}
	}
	return false
}

func (r *Roles) Identities() map[kes.Identity]string {
	r.lock.RLock()
	defer r.lock.RUnlock()

	identities := make(map[kes.Identity]string, len(r.effectiveRoles))
	for id, policy := range r.effectiveRoles {
		identities[id] = policy
	}
	return identities
}

func (r *Roles) Forget(id kes.Identity) {
	r.lock.Lock()
	delete(r.effectiveRoles, id)
	r.lock.Unlock()
}

func (r *Roles) Verify(req *http.Request) error {
	if req.TLS == nil {
		// This can only happen if the server accepts non-TLS
		// connections - which violates our fundamental security
		// assumption. Therefore, we respond with BadRequest
		// and log that the server is not correctly configured.
		return kes.NewError(http.StatusBadRequest, "insecure connection: TLS required")
	}

	if len(req.TLS.PeerCertificates) > 1 {
		// For now we require that the client sends
		// only one certificate. However, it's possible
		// to support multiple - but we have to think
		// about the semantics.
		return kes.NewError(http.StatusBadRequest, "too many identities: more than one certificate is present")
	}

	identity := Identify(req, r.Identify)
	if identity.IsUnknown() {
		return kes.ErrNotAllowed
	}
	if identity == r.Root {
		return nil
	}

	var policy *kes.Policy
	r.lock.RLock()
	if r.roles != nil && r.effectiveRoles != nil {
		if name, ok := r.effectiveRoles[identity]; ok {
			policy = r.roles[name]
		}
	}
	r.lock.RUnlock()

	if policy == nil {
		return kes.ErrNotAllowed
	}
	return policy.Verify(req)
}

// Identify computes the idenitiy of the X.509
// certificate presented by the peer who sent
// the request.
//
// It returns IdentityUnknown if no TLS connection
// state is present, more than one certificate
// is present or when f returns IdentityUnknown.
func Identify(req *http.Request, f IdentityFunc) kes.Identity {
	if req.TLS == nil {
		return kes.IdentityUnknown
	}
	if len(req.TLS.PeerCertificates) > 1 {
		return kes.IdentityUnknown
	}

	var cert *x509.Certificate
	if len(req.TLS.PeerCertificates) > 0 {
		cert = req.TLS.PeerCertificates[0]
	}
	if f == nil {
		return defaultIdentify(cert)
	}
	return f(cert)
}

// defaultIdentify computes the SHA-256 of the
// public key in cert and returns it as hex.
func defaultIdentify(cert *x509.Certificate) kes.Identity {
	if cert == nil {
		return kes.IdentityUnknown
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(h[:]))
}
