// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"time"

	"github.com/minio/kes-go"
)

// Request / Response types for the top-level `/v1` APIs

type VersionRespose struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

type StatusResponse struct {
	Version    string        `json:"version"`
	OS         string        `json:"os"`
	Arch       string        `json:"arch"`
	UpTime     time.Duration `json:"uptime"`
	CPUs       int           `json:"num_cpu"`
	UsableCPUs int           `json:"num_cpu_used"`
	HeapAlloc  uint64        `json:"mem_heap_used"`
	StackAlloc uint64        `json:"mem_stack_used"`

	KeyStoreLatency     int64 `json:"keystore_latency,omitempty"`
	KeyStoreUnavailable bool  `json:"keystore_unavailable,omitempty"`
	KeyStoreUnreachable bool  `json:"keystore_unreachable,omitempty"`
}

type ListAPIsResponse struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	MaxBody int64  `json:"max_body"`
	Timeout int64  `json:"timeout"` // Timeout in seconds
}

type DescribeEnclaveResponse struct {
	Name      string       `json:"name"`
	CreatedAt time.Time    `json:"created_at"`
	CreatedBy kes.Identity `json:"created_by"`
}

type ListEnclavesResponse struct {
	Names      []string `json:"names"`
	ContinueAt string   `json:"continue_at,omitempty"`
}

// Request / Response types for the '/v1/key/*' API

type CreateKeyRequest struct{}

type CreateKeyVersionRequest struct{}

type ImportKeyRequest struct {
	Key    []byte `json:"key"`
	Cipher string `json:"cipher"`
}

type DescribeKeyResponse struct {
	Name      string       `json:"name"`
	Version   uint32       `json:"version,omitempty"`
	CreatedAt time.Time    `json:"created_at,omitempty"`
	CreatedBy kes.Identity `json:"created_by,omitempty"`
}

type GenerateKeyRequest struct {
	Context []byte `json:"context"`
}

type GenerateKeyResponse struct {
	Plaintext  []byte `json:"plaintext"`
	Ciphertext []byte `json:"ciphertext"`
}

type EncryptKeyRequest struct {
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context"`
}

type EncryptKeyResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

type DecryptKeyRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context"`
}

type DecryptKeyResponse struct {
	Plaintext []byte `json:"plaintext"`
}

type DecryptKeyBulkRequest struct{}

type DecryptKeyBulkResponse struct{}

type ListKeysResponse struct {
	Names      []string `json:"names"`
	ContinueAt string   `json:"continue_at,omitempty"`
}

type ListKeyVersionsResponse struct{}

// Request / Response types for the '/v1/secret/*' API

type CreateSecretRequest struct {
	Secret []byte `json:"secret"`
}

type CreateSecretVersion struct{}

type DescribeSecretResponse struct {
	Version   uint32       `json:"version"`
	CreatedAt time.Time    `json:"created_at,omitempty"`
	CreatedBy kes.Identity `json:"created_by,omitempty"`
}

type ReadSecretResponse struct {
	Version   uint32       `json:"version"`
	Value     []byte       `json:"secret"`
	CreatedAt time.Time    `json:"created_at,omitempty"`
	CreatedBy kes.Identity `json:"created_by,omitempty"`
}

type ListSecretsResponse struct{}

type ListSecretVersionsResponse struct{}

// Request / Response types for the '/v1/policy/*' API

type AssignPolicyRequest struct{}

type CreatePolicyRequest struct {
	Allow map[string]struct{} `json:"allow"`
	Deny  map[string]struct{} `json:"deny"`
}

type DescribePolicyResponse struct {
	CreatedAt time.Time    `json:"created_at,omitempty"`
	CreatedBy kes.Identity `json:"created_by,omitempty"`
}

type UpdatePolicyRequest struct{}

type ReadPolicyResponse struct {
	Allow     map[string]struct{} `json:"allow,omitempty"`
	Deny      map[string]struct{} `json:"deny,omitempty"`
	CreatedAt time.Time           `json:"created_at,omitempty"`
	CreatedBy kes.Identity        `json:"created_by,omitempty"`
}

type ListPoliciesResponse struct {
	Names      []string `json:"names"`
	ContinueAt string   `json:"continue_at"`
}

// Request / Response types for the '/v1/identity/*' API

type CreateIdentityRequest struct {
	Policy  string `json:"policy"`
	IsAdmin bool   `json:"admin"`
	TTL     string `json:"ttl"`
}

type DescribeIdentityResponse struct {
	Policy    string         `json:"policy"`
	IsAdmin   bool           `json:"admin,omitempty"`
	TTL       string         `json:"ttl,omitempty"`
	ExpiresAt time.Time      `json:"expires_at,omitempty"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
	CreatedBy kes.Identity   `json:"created_by,omitempty"`
	Children  []kes.Identity `json:"children,omitempty"`
}

type SelfDescribeIdentityResponse struct {
	Identity  kes.Identity   `json:"identity"`
	IsAdmin   bool           `json:"admin,omitempty"`
	TTL       string         `json:"ttl,omitempty"`
	ExpiresAt time.Time      `json:"expires_at,omitempty"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
	CreatedBy kes.Identity   `json:"created_by,omitempty"`
	Children  []kes.Identity `json:"children,omitempty"`

	Policy string              `json:"policy,omitempty"`
	Allow  map[string]struct{} `json:"allow,omitempty"`
	Deny   map[string]struct{} `json:"deny,omitempty"`
}

type ListIdentitiesResponse struct {
	Identities []kes.Identity `json:"identities"`
	ContinueAt string         `json:"continue_at"`
}

// Request / Response types for the /v1/cluster/ API

type ExpandClusterRequest struct {
	NodeAddr string `json:"endpoint"`
}

type DescribeClusterResponse struct {
	Nodes  map[uint64]string `json:"nodes"`
	Leader uint64            `json:"leader_id"`
}

type ShrinkClusterRequest struct {
	NodeAddr string `json:"endpoint"`
}

type ForwardRPCRequest struct {
	NodeID      int    `json:"node_id"`
	CommandType uint   `json:"cmd_type"`
	Command     []byte `json:"cmd"`
}

type ReplicateRPCRequest struct {
	NodeID      int    `json:"node_id"`
	Commit      uint64 `json:"commit"`
	CommandType uint   `json:"cmd_type"`
	Command     []byte `json:"cmd"`
}

type VoteRPCRequest struct {
	NodeID int    `json:"node_id"`
	Commit uint64 `json:"commit"`
}
