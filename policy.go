// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/pelletier/go-toml"
)

// IdentityUnknown is the identity returned
// by an IdentityFunc if it cannot map a
// particular X.509 certificate to an actual
// identity.
const IdentityUnknown Identity = ""

// An Identity should uniquely identify a client and
// is computed from the X.509 certificate presented
// by the client during the TLS handshake using an
// IdentityFunc.
type Identity string

// IsUnknown returns true if and only if the
// identity is IdentityUnknown.
func (id Identity) IsUnknown() bool { return id == IdentityUnknown }

// String returns the string representation of
// the identity.
func (id Identity) String() string { return string(id) }

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
type IdentityFunc func(*x509.Certificate) Identity

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
	return func(cert *x509.Certificate) Identity {
		if cert == nil {
			return IdentityUnknown
		}
		h := hash.New()
		h.Write(cert.RawSubjectPublicKeyInfo)
		return Identity(hex.EncodeToString(h.Sum(nil)))
	}
}

type Policy struct {
	patterns []string
}

func (p Policy) MarshalJSON() ([]byte, error) {
	type PolicyJSON struct {
		Patterns []string `json:"paths"`
	}
	return json.Marshal(PolicyJSON{
		Patterns: p.patterns,
	})
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()

	var policyJSON struct {
		Patterns []string `json:"paths"`
	}
	if err := d.Decode(&policyJSON); err != nil {
		return err
	}
	for _, pattern := range policyJSON.Patterns {
		if _, err := path.Match(pattern, ""); err != nil {
			return err
		}
	}
	p.patterns = policyJSON.Patterns
	return nil
}

func (p Policy) MarshalTOML() ([]byte, error) {
	type PolicyTOML struct {
		Patterns []string `toml:"paths"`
	}
	return toml.Marshal(PolicyTOML{
		Patterns: p.patterns,
	})
}

func (p *Policy) UnmarshalTOML(b []byte) error {
	var policyTOML struct {
		Patterns []string `toml:"paths"`
	}

	if err := toml.Unmarshal(b, &policyTOML); err != nil {
		return err
	}
	for _, pattern := range policyTOML.Patterns {
		if _, err := path.Match(pattern, ""); err != nil {
			return err
		}
	}
	p.patterns = policyTOML.Patterns
	return nil
}

func (p *Policy) String() string {
	var builder strings.Builder
	fmt.Fprintln(&builder, "[")
	for _, pattern := range p.patterns {
		fmt.Fprintf(&builder, "  %s\n", pattern)
	}
	fmt.Fprintln(&builder, "]")
	return builder.String()
}

func NewPolicy(patterns ...string) *Policy {
	return &Policy{
		patterns: patterns,
	}
}

var errForbidden = NewError(http.StatusForbidden, "prohibited by policy")

func (p *Policy) Verify(r *http.Request) error {
	for _, pattern := range p.patterns {
		if ok, err := path.Match(pattern, r.URL.Path); ok && err == nil {
			return nil
		}
	}
	return errForbidden
}

type Roles struct {
	Root     Identity
	Identify IdentityFunc

	lock           sync.RWMutex
	roles          map[string]*Policy  // all available roles
	effectiveRoles map[Identity]string // identities for which a mapping to a policy name exists
}

func (r *Roles) Set(name string, policy *Policy) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*Policy{}
	}
	r.roles[name] = policy
}

func (r *Roles) Get(name string) (*Policy, bool) {
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
	delete(r.roles, name)
	r.lock.Unlock()
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

func (r *Roles) Assign(name string, id Identity) error {
	if id == r.Root {
		return errors.New("key: identity is root")
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*Policy{}
	}
	_, ok := r.roles[name]
	if !ok {
		return errors.New("key: policy does not exists")
	}
	if r.effectiveRoles == nil {
		r.effectiveRoles = map[Identity]string{}
	}
	r.effectiveRoles[id] = name
	return nil
}

func (r *Roles) IsAssigned(id Identity) bool {
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

func (r *Roles) Identities() map[Identity]string {
	r.lock.RLock()
	defer r.lock.RUnlock()

	identities := make(map[Identity]string, len(r.effectiveRoles))
	for id, policy := range r.effectiveRoles {
		identities[id] = policy
	}
	return identities
}

func (r *Roles) Forget(id Identity) {
	r.lock.Lock()
	delete(r.effectiveRoles, id)
	r.lock.Unlock()
}

func (r *Roles) enforce(req *http.Request) error {
	if req.TLS == nil {
		// This can only happen if the server accepts non-TLS
		// connections - which violates our fundamental security
		// assumption. Therefore, we respond with BadRequest
		// and log that the server is not correctly configured.
		return NewError(http.StatusBadRequest, "insecure connection: TLS required")
	}

	if len(req.TLS.PeerCertificates) > 1 {
		// For now we require that the client sends
		// only one certificate. However, it's possible
		// to support multiple - but we have to think
		// about the semantics.
		return NewError(http.StatusBadRequest, "too many identities: more than one certificate is present")
	}

	identity := Identify(req, r.Identify)
	if identity.IsUnknown() {
		return errForbidden
	}
	if identity == r.Root {
		return nil
	}

	var policy *Policy
	r.lock.RLock()
	if r.roles != nil && r.effectiveRoles != nil {
		if name, ok := r.effectiveRoles[identity]; ok {
			policy = r.roles[name]
		}
	}
	r.lock.RUnlock()

	if policy == nil {
		return errForbidden
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
func Identify(req *http.Request, f IdentityFunc) Identity {
	if req.TLS == nil {
		return IdentityUnknown
	}
	if len(req.TLS.PeerCertificates) > 1 {
		return IdentityUnknown
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
func defaultIdentify(cert *x509.Certificate) Identity {
	if cert == nil {
		return IdentityUnknown
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Identity(hex.EncodeToString(h[:]))
}
