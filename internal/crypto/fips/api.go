// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fips

import (
	"crypto/hmac"
	"crypto/tls"
	"encoding/binary"
	"hash"
)

// FIPS 140 modes define the compliance modes for FIPS 140-2 standard.
const (
	// ModeNone imposes no FIPS compliance restrictions on the
	// cryptographic primitives.
	//
	// Refer to the Mode documentation for a more detailed description.
	ModeNone = iota

	// ModeCompat represents the compatibility mode for FIPS 140 compliance.
	//
	// Refer to the Mode documentation for a more detailed description.
	ModeCompat

	// ModeStrict represents the strict mode for FIPS 140 compliance.
	//
	// Refer to the Mode documentation for a more detailed description.
	ModeStrict
)

// Mode reports the level of FIPS compliance required by the application.
//
// The default mode, ModeNone, does not impose any compliance restrictions on the
// cryptographic primitives used. It allows the usage of non-FIPS compliant primitives
// like ChaCha20Poly1305 or Curve25519.
//
// In ModeCompat, which requires the 'fips' build tag via 'go build -tags=fips',
// the application must only use FIPS compliant crypto primitives. However, these
// primitives may not necessarily be implemented by a FIPS certified module, such as
// the BoringSSL C library. For example, in ModeCompat, cryptographic primitives
// like ChaCha20Poly1305 are not allowed, and only NIST-approved primitives like
// AES, SHA2, or SHA3 should be used. The implementation can either be the regular
// Go/assembly or the BoringSSL implementation. ModeCompat ensures the use of
// approved algorithms without enforcing a certified implementation.
//
// In ModeStrict, which requires the 'fips_strict' build tag via 'go build -tags=fips_strict',
// the application must use FIPS compliant crypto primitives implemented by BoringSSL.
// This excludes primitives like Curve25519 and SHA3. ModeStrict enforces the use of
// BoringSSL's boringcrypto and is only available on the linux/amd64 platform.
//
// # Security considerations
//
// It is important to note that FIPS compatibility should not be considered a security enhancement
// in and of itself. It should only be enabled when required by policy or regulatory compliance.
// When FIPS compliance is requested, ModeCompat is typically sufficient, as it offers the following
// advantages over ModeStrict:
//   - Dependency on BoringSSL (Cgo) is optional.
//   - Cross-platform builds are supported, not limited to linux/amd64.
//   - More advanced primitives, like SHA3 or Curve25519, are available.
//   - Provides more ergonomic APIs for client applications, allowing for features like
//     misuse-resistant implementation and avoiding limitations on requests or key rotation.
const Mode = mode

// TLSCiphers returns a list of supported TLS transport
// cipher suite IDs.
func TLSCiphers() []uint16 {
	if Mode == ModeCompat || mode == ModeStrict {
		return []uint16{
			tls.TLS_AES_128_GCM_SHA256, // TLS 1.3
			tls.TLS_AES_256_GCM_SHA384,

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // TLS 1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	}
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256, // TLS 1.3
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,

		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // TLS 1.2
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// TLSCurveIDs returns a list of supported elliptic curve IDs
// in preference order.
func TLSCurveIDs() []tls.CurveID {
	if Mode == ModeCompat || Mode == ModeStrict {
		return []tls.CurveID{
			tls.CurveP256,
			tls.CurveP384, // Contant time since Go 1.18
			tls.CurveP521, // Constat time since Go 1.18
		}
	}
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384, // Contant time since Go 1.18
		tls.CurveP521, // Contant time since Go 1.18
	}
}

// DeriveKey derives a key as defined in Section 4.1 of the NIST.SP.800-108r1 publication.
// It uses the specified hash function as PRF.
//
// Ref: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf (Section 4.1)
//
// The returned byte string is outLen bytes long. The label identifies the purpose for the
// derived key material. For example, the protocol. The context provides additional context
// information for the key derivation process. It may contain randomness, like a nonce.
func DeriveKey(h func() hash.Hash, key []byte, outLen uint32, label, context []byte) []byte {
	var counter, length [4]byte
	binary.LittleEndian.PutUint32(length[:], outLen)

	prf := hmac.New(h, key)
	n := outLen / uint32(prf.Size())
	if outLen%uint32(prf.Size()) > 0 {
		n++
	}
	sum := make([]byte, prf.Size())
	out := make([]byte, 0, n*uint32(prf.Size()))
	for i := uint32(1); i <= n; i++ {
		binary.LittleEndian.PutUint32(counter[:], i)

		prf.Write(counter[:])
		prf.Write(label)
		prf.Write([]byte{0}) // padding byte
		prf.Write(context)
		prf.Write(length[:])

		sum = prf.Sum(sum[:0])
		out = append(out, sum...)
		prf.Reset()
	}
	return out[:outLen:outLen]
}
