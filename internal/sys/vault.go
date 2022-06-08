// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"context"
	"net/http"

	"github.com/minio/kes"
)

// ErrSealed is returned when a Vault has been sealed.
var ErrSealed = kes.NewError(http.StatusForbidden, "system is sealed")

// A Vault manages a set of Enclaves.
//
// It is either in a sealed or unsealed state. When the
// Vault is sealed it does not process any requests except
// unseal requests. Once unsealed, Vault provides access
// to existing enclaves.
type Vault interface {
	// Seal seals the Vault. Once sealed, any subsequent operation
	// returns ErrSealed.
	//
	// It returns ErrSealed if the Vault is already sealed.
	Seal(ctx context.Context) error

	// Unseal unseals the Vault.
	//
	// It returns no error If the Vault is already unsealed.
	Unseal(ctx context.Context, keys ...UnsealKey) error

	// Operator returns the identity of the Vault operator.
	SysAdmin(context.Context) (kes.Identity, error)

	// CreateEnclave creates and returns a new Enclave if and only if
	// no Enclave with the given name exists.
	//
	// It returns ErrEnclaveExists if an Enclave with the given name
	// already exists.
	CreateEnclave(ctx context.Context, name string, admin kes.Identity) (*EnclaveInfo, error)

	// GetEnclave returns the Enclave associated with the given name.
	//
	// It returns ErrEnclaveNotFound if no Enclave with the given
	// name exists.
	GetEnclave(ctx context.Context, name string) (*Enclave, error)

	// DeleteEnclave deletes the Enclave with the given name.
	DeleteEnclave(ctx context.Context, name string) error
}
