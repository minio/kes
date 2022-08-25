// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"context"
	"fmt"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
)

// VaultFS provides access to Vault state.
type VaultFS interface {
	// Seal seals the VaultFS. A sealed VaultFS must
	// be unsealed before it can process any new
	// requests.
	Seal(ctx context.Context) error

	// Unseal unseals a sealed VaultFS.
	Unseal(ctx context.Context, unsealKeys ...UnsealKey) error

	// Admin returns the current VaultFS admin identity.
	Admin(ctx context.Context) (kes.Identity, error)

	// CreateEnclave creates a new enclave with the given identity
	// as enclave admin.
	//
	// It returns ErrEnclaveExists if such an enclave already exists.
	CreateEnclave(ctx context.Context, name string, admin kes.Identity) (*EnclaveInfo, error)

	// GetEnclave returns the requested enclave.
	//
	// It returns ErrEnclaveNotFound if no such enclave exists.
	GetEnclave(ctx context.Context, name string) (*Enclave, error)

	// DeleteEnclave deletes the specified enclave.
	//
	// It returns ErrEnclaveNotFound if no such enclave exists.
	DeleteEnclave(ctx context.Context, name string) error
}

// KeyFS provides access to cryptographic keys within a particular
// Enclave.
type KeyFS interface {
	// CreateKey creates a new entry for the given key if and only
	// if no such entry exists already.
	//
	// It returns ErrKeyExists if such a key already exists.
	CreateKey(ctx context.Context, name string, key key.Key) error

	// GetKey returns the requested key.
	//
	// It returns ErrKeyNotFound if no such key exists.
	GetKey(ctx context.Context, name string) (key.Key, error)

	// DeleteKey deletes the specified key.
	//
	// It returns ErrKeyNotFound if no such key exists.
	DeleteKey(ctx context.Context, name string) error

	// ListKeys returns an iterator over all key entries.
	ListKeys(ctx context.Context) (key.Iterator, error)
}

// PolicyFS provides access to policies within a particular Enclave.
type PolicyFS interface {
	// SetPolicy creates or overwrites any existing policy with the
	// given one.
	SetPolicy(ctx context.Context, name string, policy auth.Policy) error

	// GetPolicy returns the requested policy.
	//
	// It returns ErrPolicyNotFound if no such policy exists.
	GetPolicy(ctx context.Context, name string) (auth.Policy, error)

	// DeletePolicy deletes the specified policy.
	//
	// It returns ErrPolicyNotFound if no such policy exists.
	DeletePolicy(ctx context.Context, name string) error

	// ListPolicies returns an iterator over all policy entries.
	ListPolicies(ctx context.Context) (auth.PolicyIterator, error)
}

// IdentityFS provides access to identities, including the admin
// identity, within a particular Enclave.
type IdentityFS interface {
	// Admin returns the enclave admin identity.
	Admin(ctx context.Context) (kes.Identity, error)

	// SetAdmin sets the enclave admin to the given identity.
	//
	// The new admin identity must not be an existing identity
	// that is already assigned to a policy.
	SetAdmin(ctx context.Context, admin kes.Identity) error

	// AssignPolicy assigns the policy to the given identity.
	//
	// No policy must be assigned to the admin identity.
	AssignPolicy(ctx context.Context, policy string, identity kes.Identity) error

	// GetIdentity returns identity information for the given identity,
	// including the admin identity information.
	//
	// It returns ErrIdentityNotFound if no such identity exists.
	GetIdentity(ctx context.Context, identity kes.Identity) (auth.IdentityInfo, error)

	// DeleteIdentity deletes the identity information for the
	// specified identity.
	//
	// It returns ErrIdentityNotFound if no such identity exists.
	DeleteIdentity(ctx context.Context, identity kes.Identity) error

	// ListIdentities returns an iterator over all identities within
	// the enclave.
	ListIdentities(ctx context.Context) (auth.IdentityIterator, error)
}

func valid(name string) error {
	for _, c := range name {
		if c == '.' || c == '\\' || c == '/' {
			return fmt.Errorf("sys: path contains invalid character %c", c)
		}
	}
	return nil
}
