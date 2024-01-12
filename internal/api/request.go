// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

// ImportKeyRequest is the request sent by clients when calling the ImportKey API.
type ImportKeyRequest struct {
	Bytes  []byte `json:"key"`
	Cipher string `json:"cipher"`
}

// EncryptKeyRequest is the request sent by clients when calling the EncryptKey API.
type EncryptKeyRequest struct {
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context"` // optional
}

// GenerateKeyRequest is the request sent by clients when calling the GenerateKey API.
type GenerateKeyRequest struct {
	Context []byte `json:"context"` // optional
}

// DecryptKeyRequest is the request sent by clients when calling the DecryptKey API.
type DecryptKeyRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context"` // optional
}

// HMACRequest is the request sent by clients when calling the HMAC API.
type HMACRequest struct {
	Message []byte `json:"message"`
}
