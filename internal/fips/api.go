// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fips

import "crypto/tls"

// Enabled indicates whether cryptographic primitives,
// like AES or SHA-256, are implemented using a FIPS 140
// certified module.
//
// If FIPS-140 is enabled no non-NIST/FIPS approved
// primitives must be used.
const Enabled = enabled

// TLSCiphers returns a list of supported TLS transport
// cipher suite IDs.
func TLSCiphers() []uint16 {
	if Enabled {
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
	if Enabled {
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
