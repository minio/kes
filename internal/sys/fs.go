// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/secret"
	"github.com/minio/kes/kms"
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
	CreateEnclave(ctx context.Context, name string, admin kes.Identity) (EnclaveInfo, error)

	// GetEnclave returns the requested enclave.
	//
	// It returns ErrEnclaveNotFound if no such enclave exists.
	GetEnclave(ctx context.Context, name string) (*Enclave, error)

	// GetEnclaveInfo returns information about the specified enclave.
	//
	// It returns ErrEnclaveNotFound if no such enclave exists.
	GetEnclaveInfo(ctx context.Context, name string) (EnclaveInfo, error)

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
	ListKeys(ctx context.Context) (kms.Iter, error)
}

// SecretFS provides access to secrets within a particular
// Enclave.
type SecretFS interface {
	// CreateSecret creates a new entry for the given secret
	// if and only if no such entry exists already.
	//
	// It returns ErrSecretExists if such a secret already exists.
	CreateSecret(ctx context.Context, name string, secret secret.Secret) error

	// GetSecret returns the requested secret.
	//
	// It returns ErrSecretNotFound if no such secret exists.
	GetSecret(ctx context.Context, name string) (secret.Secret, error)

	// DeleteSecret deletes the specified secret.
	//
	// It returns ErrSecretNotFound if no such secret exists.
	DeleteSecret(ctx context.Context, name string) error

	// ListSecrets returns an iterator over all secret entries.
	ListSecrets(ctx context.Context) (secret.Iter, error)
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

func createFile(filename string, key key.Key, plaintext, associatedData []byte) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	ciphertext, err := key.Wrap(plaintext, associatedData)
	if err != nil {
		return err
	}

	n, err := file.Write(ciphertext)
	if err != nil {
		return err
	}
	if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return file.Close()
}

func readFile(filename string, key key.Key, limit mem.Size, associatedData []byte) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ciphertext bytes.Buffer
	if _, err := io.Copy(&ciphertext, mem.LimitReader(file, limit)); err != nil {
		return nil, err
	}
	plaintext, err := key.Unwrap(ciphertext.Bytes(), associatedData)
	if err != nil {
		return nil, err
	}
	return plaintext, file.Close()
}

type iter struct {
	ctx   context.Context
	file  *os.File
	names []string

	err    error
	closed bool
}

func (i *iter) Next() bool {
	if i.closed || i.err != nil {
		return false
	}
	if len(i.names) > 0 {
		i.names = i.names[1:]
		return true
	}

	select {
	case <-i.ctx.Done():
		i.Close()
		if i.err == nil {
			i.err = i.ctx.Err()
		}
		return false
	default:
	}

	i.names, i.err = i.file.Readdirnames(250)
	if i.err == nil {
		return true
	}
	if len(i.names) > 0 && errors.Is(i.err, io.EOF) {
		i.err = nil
		return true
	}
	return false
}

func (i *iter) Name() string {
	if len(i.names) > 0 {
		return i.names[0]
	}
	return ""
}

func (i *iter) Close() error {
	if !i.closed {
		i.closed = true
		i.err = i.file.Close()
	}
	return i.err
}
