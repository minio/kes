// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
)

// NewEnclave returns a new Enclave with the
// given key store, policy set and identity set.
func NewEnclave(keys key.Store, policies auth.PolicySet, identities auth.IdentitySet) *Enclave {
	return &Enclave{
		keys:       keys,
		policies:   policies,
		identities: identities,
	}
}

// An Enclave is shielded environment with a Vault that
// stores keys, policies and identities.
type Enclave struct {
	keys key.Store

	policies auth.PolicySet

	identities auth.IdentitySet
}

// Status returns the current state of the key store.
//
// If Status fails to reach the Store - e.g.
// due to a network error - it returns a
// StoreState with StoreUnreachable and no
// error.
func (e *Enclave) Status(ctx context.Context) (key.StoreState, error) { return e.keys.Status(ctx) }

// CreateKey stores the given key if and only if no entry with
// the given name exists.
//
// It returns kes.ErrKeyExists if such an entry exists.
func (e *Enclave) CreateKey(ctx context.Context, name string, key key.Key) error {
	return e.keys.Create(ctx, name, key)
}

// DeleteKey deletes the key associated with the given name.
func (e *Enclave) DeleteKey(ctx context.Context, name string) error {
	return e.keys.Delete(ctx, name)
}

// GetKey returns the key associated with the given name.
//
// It returns kes.ErrKeyNotFound if no such entry exists.
func (e *Enclave) GetKey(ctx context.Context, name string) (key.Key, error) {
	return e.keys.Get(ctx, name)
}

// ListKeys returns a new iterator over all keys within the
// Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. creation or deletion of keys - are reflected.
// It does not provide any ordering guarantees.
func (e *Enclave) ListKeys(ctx context.Context) (key.Iterator, error) {
	return e.keys.List(ctx)
}

// SetPolicy creates or overwrites the policy with the given name.
func (e *Enclave) SetPolicy(ctx context.Context, name string, policy *auth.Policy) error {
	return e.policies.Set(ctx, name, policy)
}

// DeletePolicy deletes the policy associated with the given name.
func (e *Enclave) DeletePolicy(ctx context.Context, name string) error {
	return e.policies.Delete(ctx, name)
}

// GetPolicy returns the policy associated with the given name.
//
// It returns kes.ErrPolicyNotFound when no such entry exists.
func (e *Enclave) GetPolicy(ctx context.Context, name string) (*auth.Policy, error) {
	return e.policies.Get(ctx, name)
}

// ListPolicies returns a new iterator over all policies within
// the Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. creation or deletion of policies - are
// reflected. It does not provide any ordering guarantees.
func (e *Enclave) ListPolicies(ctx context.Context) (auth.PolicyIterator, error) {
	return e.policies.List(ctx)
}

// AssignPolicy assigns the policy to the identity.
func (e *Enclave) AssignPolicy(ctx context.Context, policy string, identity kes.Identity) error {
	return e.identities.Assign(ctx, policy, identity)
}

// DeleteIdentity deletes the given identity.
func (e *Enclave) DeleteIdentity(ctx context.Context, identities kes.Identity) error {
	return e.identities.Delete(ctx, identities)
}

// GetIdentity returns metadata about the given identity.
func (e *Enclave) GetIdentity(ctx context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	return e.identities.Get(ctx, identity)
}

// ListIdentities returns an iterator over all identites within
// the Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. assignment or deletion of identities - are
// reflected. It does not provide any ordering guarantees.
func (e *Enclave) ListIdentities(ctx context.Context) (auth.IdentityIterator, error) {
	return e.identities.List(ctx)
}

// VerifyRequest verifies the given request is allowed
// based on the policies and identities within the Enclave.
func (e *Enclave) VerifyRequest(r *http.Request) error {
	if r.TLS == nil {
		return kes.NewError(http.StatusBadRequest, "insecure connection: TLS required")
	}

	var peerCertificates []*x509.Certificate
	switch {
	case len(r.TLS.PeerCertificates) <= 1:
		peerCertificates = r.TLS.PeerCertificates
	case len(r.TLS.PeerCertificates) > 1:
		for _, cert := range r.TLS.PeerCertificates {
			if cert.IsCA {
				continue
			}
			peerCertificates = append(peerCertificates, cert)
		}
	}
	if len(peerCertificates) == 0 {
		return kes.NewError(http.StatusBadRequest, "no client certificate is present")
	}
	if len(peerCertificates) > 1 {
		return kes.NewError(http.StatusBadRequest, "too many client certificates are present")
	}

	var (
		h        = sha256.Sum256(peerCertificates[0].RawSubjectPublicKeyInfo)
		identity = kes.Identity(hex.EncodeToString(h[:]))
	)
	admin, err := e.identities.Admin(r.Context())
	if err != nil {
		return err
	}
	if identity == admin {
		return nil
	}

	info, err := e.GetIdentity(r.Context(), identity)
	if errors.Is(err, auth.ErrIdentityNotFound) {
		return kes.ErrNotAllowed
	}
	if err != nil {
		return err
	}
	policy, err := e.GetPolicy(r.Context(), info.Policy)
	if err != nil {
		return err
	}
	return policy.Verify(r)
}
