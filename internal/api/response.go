// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"time"
)

// VersionResponse is the response sent to clients by the Version API.
type VersionResponse struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// StatusResponse is the response sent to clients by the Status API.
type StatusResponse struct {
	Version    string `json:"version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	UpTime     uint64 `json:"uptime"` // in seconds
	CPUs       int    `json:"num_cpu"`
	UsableCPUs int    `json:"num_cpu_used"`
	HeapAlloc  uint64 `json:"mem_heap_used"`
	StackAlloc uint64 `json:"mem_stack_used"`

	KeyStoreLatency     int64 `json:"keystore_latency,omitempty"` // In microseconds
	KeyStoreUnreachable bool  `json:"keystore_unreachable,omitempty"`
}

// DescribeRouteResponse describes a single API route. It is part of
// a List API response.
type DescribeRouteResponse struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	MaxBody int64  `json:"max_body"`
	Timeout int64  `json:"timeout"` // in seconds
}

// ListAPIsResponse is the response sent to clients by the List APIs API.
type ListAPIsResponse []DescribeRouteResponse

// DescribeKeyResponse is the response sent to clients by the DescribeKey API.
type DescribeKeyResponse struct {
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// ListKeysResponse is the response sent to clients by the ListKeys API.
type ListKeysResponse struct {
	Names      []string `json:"names"`
	ContinueAt string   `json:"continue_at,omitempty"`
}

// EncryptKeyResponse is the response sent to clients by the EncryptKey API.
type EncryptKeyResponse struct {
	Ciphertext []byte `json:"ciphertext"`
}

// GenerateKeyResponse is the response sent to clients by the GenerateKey API.
type GenerateKeyResponse struct {
	Plaintext  []byte `json:"plaintext"`
	Ciphertext []byte `json:"ciphertext"`
}

// DecryptKeyResponse is the response sent to clients by the DecryptKey API.
type DecryptKeyResponse struct {
	Plaintext []byte `json:"plaintext"`
}

// HMACResponse is the response sent to clients by the HMAC API.
type HMACResponse struct {
	Sum []byte `json:"hmac"`
}

// ReadPolicyResponse is the response sent to clients by the ReadPolicy API.
type ReadPolicyResponse struct {
	Name      string              `json:"name"`
	Allow     map[string]struct{} `json:"allow,omitempty"`
	Deny      map[string]struct{} `json:"deny,omitempty"`
	CreatedAt time.Time           `json:"created_at"`
	CreatedBy string              `json:"created_by"`
}

// DescribePolicyResponse is the response sent to clients by the DescribePolicy API.
type DescribePolicyResponse struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// ListPoliciesResponse is the response sent to clients by the ListPolicies API.
type ListPoliciesResponse struct {
	Names      []string `json:"names"`
	ContinueAt string   `json:"continue_at"`
}

// DescribeIdentityResponse is the response sent to clients by the DescribeIdentity API.
type DescribeIdentityResponse struct {
	IsAdmin   bool      `json:"admin,omitempty"`
	Policy    string    `json:"policy,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`
}

// ListIdentitiesResponse is the response sent to clients by the ListIdentities API.
type ListIdentitiesResponse struct {
	Identities []string `json:"identities"`
	ContinueAt string   `json:"continue_at"`
}

// SelfDescribeIdentityResponse is the response sent to clients by the SelfDescribeIdentity API.
type SelfDescribeIdentityResponse struct {
	Identity  string    `json:"identity"`
	IsAdmin   bool      `json:"admin,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by,omitempty"`

	Policy *ReadPolicyResponse `json:"policy,omitempty"`
}

// AuditLogEvent is sent to clients (as stream of events) when they subscribe to the AuditLog API.
type AuditLogEvent struct {
	Time     time.Time        `json:"time"`
	Request  AuditLogRequest  `json:"request"`
	Response AuditLogResponse `json:"response"`
}

// AuditLogRequest describes a client request in an AuditLogEvent.
type AuditLogRequest struct {
	IP       string `json:"ip,omitempty"`
	APIPath  string `json:"path"`
	Identity string `json:"identity,omitempty"`
}

// AuditLogResponse describes a server response in an AuditLogEvent.
type AuditLogResponse struct {
	StatusCode int   `json:"code"`
	Time       int64 `json:"time"` // In microseconds
}

// ErrorLogEvent is sent to clients (as stream of events) when they subscribe to the ErrorLog API.
type ErrorLogEvent struct {
	Message string `json:"message"`
}
