// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import "time"

//go:generate msgp -io=false

// Commit is the message pack representation of a kes.commit.
type Commit struct {
	N     uint64 `msg:"0"`
	Type  uint   `msg:"1"`
	Event []byte `msg:"2"`
}

// EncryptedRootKey is the message pack representation of a kes.encryptedRootKey.
type EncryptedRootKey struct {
	Ciphertexts map[string][]byte `msg:"0"`
}

// Enclave is the message pack representation of a kes.Enclave.
type Enclave struct {
	Key       SecretKey `msg:"0"`
	Admins    []string  `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

// EnclaveInfo is the message pack representation of a kes.enclaveInfo.
type EnclaveInfo struct {
	Key       SecretKey `msg:"0"`
	CreatedAt time.Time `msg:"1"`
	CreatedBy string    `msg:"2"`
}

// JoinClusterCmd is the message pack representation of a kes.joinClusterCmd.
type JoinClusterCmd struct {
	Cluster map[string]string `msg:"0"`
	Node    string            `msg:"1"`
}

// LeaveClusterCmd is the message pack representation of a kes.leaveClusterCmd.
type LeaveClusterCmd struct {
	Cluster map[string]string `msg:"0"`
	Node    string            `msg:"1"`
}

// CreateEnclaveCmd is the message pack representation of a kes.createEnclaveCmd.
type CreateEnclaveCmd struct {
	Name      string    `msg:"0"`
	Key       SecretKey `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

// DeleteEnclaveCmd is the message pack representation of a kes.deleteEnclaveCmd.
type DeleteEnclaveCmd struct {
	Name string `msg:"0"`
}

// CreateSecretKeyRingCmd is the message pack representation of a kes.createSecretKeyRingCmd.
type CreateSecretKeyRingCmd struct {
	Enclave   string    `msg:"0"`
	Name      string    `msg:"1"`
	Key       SecretKey `msg:"2"`
	CreatedAt time.Time `msg:"3"`
	CreatedBy string    `msg:"4"`
}

// DeleteSecretKeyRingCmd is the message pack representation of a kes.deleteSecretKeyRingCmd.
type DeleteSecretKeyRingCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

// CreateSecretCmd is the message pack representation of a kes.createSecretCmd.
type CreateSecretCmd struct {
	Enclave    string    `msg:"0"`
	Name       string    `msg:"1"`
	Secret     []byte    `msg:"2"`
	SecretType uint      `msg:"3"`
	CreatedAt  time.Time `msg:"4"`
	CreatedBy  string    `msg:"5"`
}

// DeleteSecretCmd is the message pack representation of a kes.deleteSecretCmd.
type DeleteSecretCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

// CreatePolicyCmd is the message pack representation of a kes.createPolicyCmd.
type CreatePolicyCmd struct {
	Enclave   string              `msg:"0"`
	Name      string              `msg:"1"`
	Allow     map[string]struct{} `msg:"2"`
	Deny      map[string]struct{} `msg:"3"`
	CreatedAt time.Time           `msg:"4"`
	CreatedBy string              `msg:"5"`
}

// DeletePolicyCmd is the message pack representation of a kes.deletePolicyCmd.
type DeletePolicyCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

// CreateIdentityCmd is the message pack representation of a kes.createIdentityCmd.
type CreateIdentityCmd struct {
	Enclave   string        `msg:"0"`
	Identity  string        `msg:"1"`
	Policy    string        `msg:"2"`
	IsAdmin   bool          `msg:"3"`
	TTL       time.Duration `msg:"4"`
	ExpiresAt time.Time     `msg:"5"`
	CreatedAt time.Time     `msg:"6"`
	CreatedBy string        `msg:"7"`
}

// DeleteIdentityCmd is the message pack representation of a kes.deleteIdentityCmd.
type DeleteIdentityCmd struct {
	Enclave  string `msg:"0"`
	Identity string `msg:"1"`
}
