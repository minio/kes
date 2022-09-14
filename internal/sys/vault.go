// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"context"
	"net/http"
	"sync"

	"github.com/minio/kes"
)

// NewVault returns a new Vault that uses the given
// VaultFS to persist state.
func NewVault(fs VaultFS) *Vault {
	return &Vault{
		fs:       fs,
		enclaves: map[string]*Enclave{},
	}
}

// A Vault manages a set of enclaves. It is either in a
// sealed or unsealed state. When sealed, any Vault operation,
// except unsealing, returns ErrSealed.
type Vault struct {
	fs   VaultFS
	lock sync.RWMutex

	cacheLock sync.Mutex
	admin     kes.Identity
	sealed    bool
	enclaves  map[string]*Enclave
}

// Locker returns a sync.Locker that locks the Vault for writes.
func (v *Vault) Locker() sync.Locker { return &v.lock }

// RLocker returns a sync.Locker that locks the Vault for reads.
func (v *Vault) RLocker() sync.Locker { return v.lock.RLocker() }

// Seal seals the Vault. Once sealed, any subsequent Vault operation,
// returns ErrSealed until the Vault gets unsealed again.
func (v *Vault) Seal(ctx context.Context) error {
	if v.sealed {
		return kes.ErrSealed
	}
	if err := v.fs.Seal(ctx); err != nil {
		return err
	}
	v.admin = ""
	v.enclaves = map[string]*Enclave{}
	v.sealed = true
	return nil
}

// Unseal unseals the Vault. In case of an unsealed Vault,
// Unseal is a no-op.
func (v *Vault) Unseal(ctx context.Context, keys ...UnsealKey) error {
	if !v.sealed {
		return nil
	}
	if err := v.fs.Unseal(ctx, keys...); err != nil {
		return err
	}
	admin, err := v.fs.Admin(ctx)
	if err != nil {
		return err
	}
	v.admin = admin
	v.enclaves = map[string]*Enclave{}
	v.sealed = false
	return nil
}

// Admin returns the current Vault admin identity.
func (v *Vault) Admin(ctx context.Context) (kes.Identity, error) {
	if !v.admin.IsUnknown() {
		return v.admin, nil
	}

	admin, err := v.fs.Admin(ctx)
	if err != nil {
		return "", err
	}

	v.cacheLock.Lock()
	v.admin = admin
	v.cacheLock.Unlock()
	return v.admin, nil
}

// CreateEnclave creates a new enclave with the given name and
// enclave admin identity.
//
// It returns ErrEnclaveExists if such an enclave already exists.
func (v *Vault) CreateEnclave(ctx context.Context, name string, admin kes.Identity) (EnclaveInfo, error) {
	if name == "" {
		name = DefaultEnclaveName
	}

	if v.sealed {
		return EnclaveInfo{}, kes.ErrSealed
	}
	if admin.IsUnknown() {
		return EnclaveInfo{}, kes.NewError(http.StatusBadRequest, "admin cannot be empty")
	}
	if admin == v.admin {
		return EnclaveInfo{}, kes.NewError(http.StatusBadRequest, "admin cannot be the system admin")
	}

	delete(v.enclaves, name)
	return v.fs.CreateEnclave(ctx, name, admin)
}

// GetEnclave returns the Enclave with the given name.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (v *Vault) GetEnclave(ctx context.Context, name string) (*Enclave, error) {
	if name == "" {
		name = DefaultEnclaveName
	}

	if v.sealed {
		return nil, kes.ErrSealed
	}
	if enclave, ok := v.enclaves[name]; ok {
		return enclave, nil
	}

	v.cacheLock.Lock()
	defer v.cacheLock.Unlock()

	if enclave, ok := v.enclaves[name]; ok {
		return enclave, nil
	}
	enclave, err := v.fs.GetEnclave(ctx, name)
	if err != nil {
		return nil, err
	}
	v.enclaves[name] = enclave
	return enclave, nil
}

// GetEnclaveInfo returns information about the specified enclave.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (v *Vault) GetEnclaveInfo(ctx context.Context, name string) (EnclaveInfo, error) {
	if name == "" {
		name = DefaultEnclaveName
	}
	if v.sealed {
		return EnclaveInfo{}, kes.ErrSealed
	}
	return v.fs.GetEnclaveInfo(ctx, name)
}

// DeleteEnclave deletes the enclave with the given name.
//
// It returns ErrEnclaveNotFound if no such enclave exists.
func (v *Vault) DeleteEnclave(ctx context.Context, name string) error {
	if name == "" {
		name = DefaultEnclaveName
	}

	if v.sealed {
		return kes.ErrSealed
	}
	delete(v.enclaves, name)
	return v.fs.DeleteEnclave(ctx, name)
}
