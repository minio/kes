// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import "time"

//go:generate msgp -io=false

type Commit struct {
	N     uint64 `msg:"0"`
	Type  uint   `msg:"1"`
	Event []byte `msg:"2"`
}

type EncryptedRootKey struct {
	Ciphertexts map[string][]byte `msg:"0"`
}

type Enclave struct {
	Key       SecretKey `msg:"0"`
	Admins    []string  `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

type EnclaveInfo struct {
	Key       SecretKey `msg:"0"`
	CreatedAt time.Time `msg:"1"`
	CreatedBy string    `msg:"2"`
}

type JoinClusterCmd struct {
	Cluster map[string]string `msg:"0"`
	Node    string            `msg:"1"`
}

type LeaveClusterCmd struct {
	Cluster map[string]string `msg:"0"`
	Node    string            `msg:"1"`
}

type CreateEnclaveCmd struct {
	Name      string    `msg:"0"`
	Key       SecretKey `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}

type DeleteEnclaveCmd struct {
	Name string `msg:"0"`
}

type CreateSecretKeyRingCmd struct {
	Enclave   string    `msg:"0"`
	Name      string    `msg:"1"`
	Key       SecretKey `msg:"2"`
	CreatedAt time.Time `msg:"3"`
	CreatedBy string    `msg:"4"`
}

type DeleteSecretKeyRingCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

type CreateSecretCmd struct {
	Enclave    string    `msg:"0"`
	Name       string    `msg:"1"`
	Secret     []byte    `msg:"2"`
	SecretType uint      `msg:"3"`
	CreatedAt  time.Time `msg:"4"`
	CreatedBy  string    `msg:"5"`
}

type DeleteSecretCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

type CreatePolicyCmd struct {
	Enclave   string              `msg:"0"`
	Name      string              `msg:"1"`
	Allow     map[string]struct{} `msg:"2"`
	Deny      map[string]struct{} `msg:"3"`
	CreatedAt time.Time           `msg:"4"`
	CreatedBy string              `msg:"5"`
}

type DeletePolicyCmd struct {
	Enclave string `msg:"0"`
	Name    string `msg:"1"`
}

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

type DeleteIdentityCmd struct {
	Enclave  string `msg:"0"`
	Identity string `msg:"1"`
}
