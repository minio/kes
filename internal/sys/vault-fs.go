// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/key"
)

// NewVaultFS returns a new VaultFS that
// reads/writes enclaves from/to the given
// directory path and en/decrypts them
// with the given encryption key.
func NewVaultFS(filename string, key key.Key) VaultFS {
	return &vaultFS{
		rootDir: filename,
		rootKey: key,
	}
}

type vaultFS struct {
	rootDir string
	rootKey key.Key
}

func (v *vaultFS) Seal(ctx context.Context) error {
	v.rootKey = key.Key{}
	return nil
}

func (v *vaultFS) Unseal(ctx context.Context, unsealKeys ...UnsealKey) error {
	file, err := os.Open(filepath.Join(v.rootDir, ".unseal"))
	if err != nil {
		return err
	}
	defer file.Close()

	const MaxSize = 1 * mem.MiB
	var buffer bytes.Buffer
	if _, err = io.Copy(&buffer, mem.LimitReader(file, MaxSize)); err != nil {
		return err
	}

	var stanza Stanza
	if err = stanza.UnmarshalBinary(buffer.Bytes()); err != nil {
		return err
	}
	rootKeyBytes, err := UnsealFromEnvironment().Unseal(&stanza)
	if err != nil {
		return err
	}
	var rootKey key.Key
	if err = rootKey.UnmarshalBinary(rootKeyBytes); err != nil {
		return err
	}
	v.rootKey = rootKey
	return nil
}

func (v *vaultFS) Admin(ctx context.Context) (kes.Identity, error) {
	return v.rootKey.CreatedBy(), nil
}

func (v *vaultFS) CreateEnclave(ctx context.Context, name string, admin kes.Identity) (EnclaveInfo, error) {
	if err := valid(name); err != nil {
		return EnclaveInfo{}, err
	}

	enclavePath := filepath.Join(v.rootDir, "enclave", name)
	_, err := os.Stat(enclavePath)
	if err == nil {
		return EnclaveInfo{}, kes.ErrEnclaveExists
	}
	if !errors.Is(err, os.ErrNotExist) {
		return EnclaveInfo{}, err
	}

	algorithm := kes.AES256_GCM_SHA256
	if !fips.Enabled && !cpu.HasAESGCM() {
		algorithm = kes.XCHACHA20_POLY1305
	}
	keyStoreKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		return EnclaveInfo{}, err
	}
	secretKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		return EnclaveInfo{}, err
	}
	policyKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		return EnclaveInfo{}, err
	}
	identityKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		return EnclaveInfo{}, err
	}

	if err = os.MkdirAll(filepath.Join(enclavePath), 0o755); err != nil {
		return EnclaveInfo{}, err
	}
	if err = os.Mkdir(filepath.Join(enclavePath, "key"), 0o755); err != nil {
		return EnclaveInfo{}, err
	}
	if err = os.Mkdir(filepath.Join(enclavePath, "secret"), 0o755); err != nil {
		return EnclaveInfo{}, err
	}
	if err = os.Mkdir(filepath.Join(enclavePath, "policy"), 0o755); err != nil {
		return EnclaveInfo{}, err
	}
	if err = os.Mkdir(filepath.Join(enclavePath, "identity"), 0o755); err != nil {
		return EnclaveInfo{}, err
	}

	identityFS := NewIdentityFS(filepath.Join(enclavePath, "identity"), identityKey)
	if err = identityFS.SetAdmin(ctx, admin); err != nil {
		return EnclaveInfo{}, err
	}

	info := EnclaveInfo{
		Name:        name,
		KeyStoreKey: keyStoreKey,
		SecretKey:   secretKey,
		PolicyKey:   policyKey,
		IdentityKey: identityKey,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   v.rootKey.CreatedBy(),
	}
	plaintext, err := info.MarshalBinary()
	if err != nil {
		return EnclaveInfo{}, err
	}
	ciphertext, err := v.rootKey.Wrap(plaintext, []byte(name))
	if err != nil {
		return EnclaveInfo{}, err
	}
	if err = os.WriteFile(filepath.Join(enclavePath, ".enclave"), ciphertext, 0o600); err != nil {
		return EnclaveInfo{}, err
	}
	return info, nil
}

func (v *vaultFS) GetEnclave(ctx context.Context, name string) (*Enclave, error) {
	if err := valid(name); err != nil {
		return nil, err
	}

	enclavePath := filepath.Join(v.rootDir, "enclave", name)
	file, err := os.Open(filepath.Join(enclavePath, ".enclave"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, kes.ErrEnclaveNotFound
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	const MaxSize = 1 * mem.MiB
	var ciphertext bytes.Buffer
	if _, err = io.Copy(&ciphertext, mem.LimitReader(file, MaxSize)); err != nil {
		return nil, err
	}
	plaintext, err := v.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		return nil, err
	}
	var info EnclaveInfo
	if err = info.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}

	keyFS := NewKeyFS(filepath.Join(enclavePath, "key"), info.KeyStoreKey)
	secretFS := NewSecretFS(filepath.Join(enclavePath, "secret"), info.SecretKey)
	policyFS := NewPolicyFS(filepath.Join(enclavePath, "policy"), info.PolicyKey)
	identityFS := NewIdentityFS(filepath.Join(enclavePath, "identity"), info.IdentityKey)
	return NewEnclave(keyFS, secretFS, policyFS, identityFS), nil
}

func (v *vaultFS) GetEnclaveInfo(ctx context.Context, name string) (EnclaveInfo, error) {
	if err := valid(name); err != nil {
		return EnclaveInfo{}, err
	}

	enclavePath := filepath.Join(v.rootDir, "enclave", name)
	file, err := os.Open(filepath.Join(enclavePath, ".enclave"))
	if errors.Is(err, os.ErrNotExist) {
		return EnclaveInfo{}, kes.ErrEnclaveNotFound
	}
	if err != nil {
		return EnclaveInfo{}, err
	}
	defer file.Close()

	const MaxSize = 1 * mem.MiB
	var ciphertext bytes.Buffer
	if _, err = io.Copy(&ciphertext, mem.LimitReader(file, MaxSize)); err != nil {
		return EnclaveInfo{}, err
	}
	plaintext, err := v.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		return EnclaveInfo{}, err
	}
	var info EnclaveInfo
	if err = info.UnmarshalBinary(plaintext); err != nil {
		return EnclaveInfo{}, err
	}
	return info, nil
}

func (v *vaultFS) DeleteEnclave(ctx context.Context, name string) error {
	if err := valid(name); err != nil {
		return err
	}
	return os.RemoveAll(filepath.Join(v.rootDir, "enclave", name))
}
