// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/secret"
	"github.com/minio/kes/kms"
)

// DefaultEnclaveName is the default Enclave name used
// when the client does not specify the Enclave name
// explicitly.
const DefaultEnclaveName = "default"

// EnclaveInfo contains information about an Enclave.
type EnclaveInfo struct {
	// Name is the Enclave's name.
	Name string

	// KeyStoreKey is the root encryption key used to
	// en/decrypt the key store.
	KeyStoreKey key.Key

	// SecretKey is the root encryption key used to
	// en/decrypt the secret store.
	SecretKey key.Key

	// PolicyKey is the root encryption key used to
	// en/decrypt the policy set.
	PolicyKey key.Key

	// IdentityKey is the root encryption key used to
	// en/decrypt the identity set.
	IdentityKey key.Key

	// CreatedAt is the point in time when the Enclave
	// got created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the Enclave.
	CreatedBy kes.Identity
}

// MarshalBinary returns the EnclaveInfo's binary representation.
func (e EnclaveInfo) MarshalBinary() ([]byte, error) {
	type GOB struct {
		Name        string
		KeyStoreKey key.Key
		SecretKey   key.Key
		PolicyKey   key.Key
		IdentityKey key.Key
		CreatedAt   time.Time
		CreatedBy   kes.Identity
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(GOB(e)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalBinary unmarshals the EnclaveInfo's binary representation.
func (e *EnclaveInfo) UnmarshalBinary(b []byte) error {
	type GOB struct {
		Name        string
		KeyStoreKey key.Key
		SecretKey   key.Key
		PolicyKey   key.Key
		IdentityKey key.Key
		CreatedAt   time.Time
		CreatedBy   kes.Identity
	}

	var value GOB
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&value); err != nil {
		return err
	}
	e.Name = value.Name
	e.KeyStoreKey = value.KeyStoreKey
	e.SecretKey = value.SecretKey
	e.PolicyKey = value.PolicyKey
	e.IdentityKey = value.IdentityKey
	e.CreatedAt = value.CreatedAt
	e.CreatedBy = value.CreatedBy
	return nil
}

// NewEnclave returns a new Enclave with the
// given key store, policy set and identity set.
func NewEnclave(keys KeyFS, secrets SecretFS, policies PolicyFS, identities IdentityFS) *Enclave {
	return &Enclave{
		keys:       keys,
		secrets:    secrets,
		policies:   policies,
		identities: identities,

		keyCache:      map[string]key.Key{},
		secretCache:   map[string]secret.Secret{},
		policyCache:   map[string]auth.Policy{},
		identityCache: map[kes.Identity]auth.IdentityInfo{},
	}
}

// An Enclave is a shielded environment within a Vault that
// stores keys, policies and identities.
type Enclave struct {
	keys       KeyFS
	secrets    SecretFS
	policies   PolicyFS
	identities IdentityFS
	lock       sync.RWMutex

	cacheLock     sync.Mutex
	admin         kes.Identity
	keyCache      map[string]key.Key
	secretCache   map[string]secret.Secret
	policyCache   map[string]auth.Policy
	identityCache map[kes.Identity]auth.IdentityInfo
}

// Locker returns a sync.Locker that locks the Enclave for writes.
func (e *Enclave) Locker() sync.Locker { return &e.lock }

// RLocker returns a sync.Locker that locks the Enclave for reads.
func (e *Enclave) RLocker() sync.Locker { return e.lock.RLocker() }

// Status returns the current state of the key store.
//
// If Status fails to reach the Store - e.g.
// due to a network error - it returns a
// StoreState with StoreUnreachable and no
// error.
func (e *Enclave) Status(ctx context.Context) (kms.State, error) { return kms.State{}, nil }

// CreateKey stores the given key if and only if no entry with
// the given name exists.
//
// It returns kes.ErrKeyExists if such an entry exists.
func (e *Enclave) CreateKey(ctx context.Context, name string, key key.Key) error {
	if _, ok := e.keyCache[name]; ok {
		return kes.ErrKeyExists
	}
	return e.keys.CreateKey(ctx, name, key)
}

// DeleteKey deletes the key associated with the given name.
func (e *Enclave) DeleteKey(ctx context.Context, name string) error {
	delete(e.keyCache, name)
	return e.keys.DeleteKey(ctx, name)
}

// GetKey returns the key associated with the given name.
//
// It returns kes.ErrKeyNotFound if no such entry exists.
func (e *Enclave) GetKey(ctx context.Context, name string) (key.Key, error) {
	if k, ok := e.keyCache[name]; ok {
		return k, nil
	}

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	if k, ok := e.keyCache[name]; ok {
		return k, nil
	}
	k, err := e.keys.GetKey(ctx, name)
	if err != nil {
		return key.Key{}, err
	}
	e.keyCache[name] = k
	return k, nil
}

// ListKeys returns a new iterator over all keys within the
// Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. creation or deletion of keys - are reflected.
// It does not provide any ordering guarantees.
func (e *Enclave) ListKeys(ctx context.Context) (kms.Iter, error) {
	return e.keys.ListKeys(ctx)
}

// CreateSecret stores the given secret if and only if no entry with
// the given name exists.
//
// It returns kes.ErrSecretExists if such an entry exists.
func (e *Enclave) CreateSecret(ctx context.Context, name string, secret secret.Secret) error {
	if _, ok := e.secretCache[name]; ok {
		return kes.ErrSecretExists
	}
	return e.secrets.CreateSecret(ctx, name, secret)
}

// GetSecret returns the secret associated with the given name.
//
// It returns kes.ErrSecretNotFound if no such entry exists.
func (e *Enclave) GetSecret(ctx context.Context, name string) (secret.Secret, error) {
	if s, ok := e.secretCache[name]; ok {
		return s, nil
	}

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	if s, ok := e.secretCache[name]; ok {
		return s, nil
	}
	s, err := e.secrets.GetSecret(ctx, name)
	if err != nil {
		return secret.Secret{}, err
	}
	e.secretCache[name] = s
	return s, nil
}

// DeleteSecret deletes the secret associated with the given name.
//
// It returns kes.ErrSecretNotFound if no such entry exists.
func (e *Enclave) DeleteSecret(ctx context.Context, name string) error {
	delete(e.secretCache, name)
	return e.secrets.DeleteSecret(ctx, name)
}

// ListSecrets returns a new iterator over all secrets within the
// Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. creation or deletion of secrets - are reflected.
// It does not provide any ordering guarantees.
func (e *Enclave) ListSecrets(ctx context.Context) (secret.Iter, error) {
	return e.secrets.ListSecrets(ctx)
}

// SetPolicy creates or overwrites the policy with the given name.
func (e *Enclave) SetPolicy(ctx context.Context, name string, policy auth.Policy) error {
	delete(e.policyCache, name)
	return e.policies.SetPolicy(ctx, name, policy)
}

// DeletePolicy deletes the policy associated with the given name.
func (e *Enclave) DeletePolicy(ctx context.Context, name string) error {
	delete(e.policyCache, name)
	return e.policies.DeletePolicy(ctx, name)
}

// GetPolicy returns the policy associated with the given name.
//
// It returns kes.ErrPolicyNotFound when no such entry exists.
func (e *Enclave) GetPolicy(ctx context.Context, name string) (auth.Policy, error) {
	if policy, ok := e.policyCache[name]; ok {
		return policy, nil
	}

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	if policy, ok := e.policyCache[name]; ok {
		return policy, nil
	}
	policy, err := e.policies.GetPolicy(ctx, name)
	if err != nil {
		return auth.Policy{}, err
	}
	e.policyCache[name] = policy
	return policy, nil
}

// ListPolicies returns a new iterator over all policies within
// the Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. creation or deletion of policies - are
// reflected. It does not provide any ordering guarantees.
func (e *Enclave) ListPolicies(ctx context.Context) (auth.PolicyIterator, error) {
	return e.policies.ListPolicies(ctx)
}

// Admin returns the current Enclave admin identity.
func (e *Enclave) Admin(ctx context.Context) (kes.Identity, error) {
	if !e.admin.IsUnknown() {
		return e.admin, nil
	}

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	if !e.admin.IsUnknown() {
		return e.admin, nil
	}
	admin, err := e.identities.Admin(ctx)
	if err != nil {
		return "", err
	}
	e.admin = admin
	return e.admin, nil
}

// SetAdmin sets the Enclave admin to the given identity. The
// new admin identity must not be an existing identity that is
// already assigned to a policy.
func (e *Enclave) SetAdmin(ctx context.Context, admin kes.Identity) error {
	if admin == e.admin {
		return nil
	}

	_, err := e.GetIdentity(ctx, admin)
	if err == nil {
		return kes.NewError(http.StatusConflict, "identity already exists")
	}
	if err != nil && !errors.Is(err, kes.ErrIdentityNotFound) {
		return err
	}

	if err := e.identities.SetAdmin(ctx, admin); err != nil {
		return err
	}
	e.admin = ""
	return nil
}

// AssignPolicy assigns the policy to the identity.
func (e *Enclave) AssignPolicy(ctx context.Context, policy string, identity kes.Identity) error {
	admin, err := e.Admin(ctx)
	if err != nil {
		return err
	}
	if identity == admin {
		return kes.NewError(http.StatusBadRequest, "cannot assign policy to admin")
	}

	delete(e.identityCache, identity)
	return e.identities.AssignPolicy(ctx, policy, identity)
}

// DeleteIdentity deletes the given identity.
func (e *Enclave) DeleteIdentity(ctx context.Context, identity kes.Identity) error {
	admin, err := e.Admin(ctx)
	if err != nil {
		return err
	}
	if identity == admin {
		return kes.NewError(http.StatusBadRequest, "cannot delete admin")
	}

	delete(e.identityCache, identity)
	return e.identities.DeleteIdentity(ctx, identity)
}

// GetIdentity returns metadata about the given identity.
func (e *Enclave) GetIdentity(ctx context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if info, ok := e.identityCache[identity]; ok {
		return info, nil
	}

	e.cacheLock.Lock()
	defer e.cacheLock.Unlock()

	if info, ok := e.identityCache[identity]; ok {
		return info, nil
	}
	info, err := e.identities.GetIdentity(ctx, identity)
	if err != nil {
		return auth.IdentityInfo{}, err
	}
	e.identityCache[identity] = info
	return info, nil
}

// ListIdentities returns an iterator over all identites within
// the Enclave.
//
// The iterator makes no guarantees about whether concurrent changes
// to the enclave - i.e. assignment or deletion of identities - are
// reflected. It does not provide any ordering guarantees.
func (e *Enclave) ListIdentities(ctx context.Context) (auth.IdentityIterator, error) {
	return e.identities.ListIdentities(ctx)
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
	info, err := e.GetIdentity(r.Context(), identity)
	if errors.Is(err, kes.ErrIdentityNotFound) {
		return kes.ErrNotAllowed
	}
	if err != nil {
		return err
	}
	if info.IsAdmin {
		return nil
	}

	policy, err := e.GetPolicy(r.Context(), info.Policy)
	if errors.Is(err, kes.ErrPolicyNotFound) {
		return kes.ErrNotAllowed
	}
	if err != nil {
		return err
	}
	return policy.Verify(r)
}
