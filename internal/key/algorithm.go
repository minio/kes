// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

// Algorithm is a cryptographic algorithm that requires
// a cryptographic key.
type Algorithm string

const (
	// AlgorithmGeneric is a generic value that indicates
	// that the key can be used with multiple algorithms.
	AlgorithmGeneric Algorithm = ""

	// AES256_GCM_SHA256 is an algorithm that uses HMAC-SHA256
	// for key derivation and AES256-GCM for en/decryption.
	AES256_GCM_SHA256 Algorithm = "AES256-GCM_SHA256"

	// XCHACHA20_POLY1305 is an algorithm that uses HChaCha20
	// for key derivation and ChaCha20-Poly1305 for en/decryption.
	XCHACHA20_POLY1305 Algorithm = "XCHACHA20-POLY1305"
)

// String returns the Algorithm's string representation.
func (a Algorithm) String() string { return string(a) }

// KeySize returns the Algorithm's key size.
func (a Algorithm) KeySize() int {
	switch a {
	case AES256_GCM_SHA256:
		return 256 / 8
	case XCHACHA20_POLY1305:
		return 256 / 8
	case AlgorithmGeneric:
		return 256 / 8 // For generic/unknown keys, return 256 bit.
	default:
		return -1
	}
}
