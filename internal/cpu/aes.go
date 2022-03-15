// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cpu

import (
	"runtime"

	"golang.org/x/sys/cpu"
)

// HasAESGCM returns true if and only if the CPU
// provides native hardware instructions for AES-GCM.
func HasAESGCM() bool {
	// Go 1.14 introduced an AES-GCM asm implementation for PPC64-le.
	// PPC64 always provides hardware support for AES-GCM.
	// Ref: https://go.dev/src/crypto/aes/gcm_ppc64le.go
	if runtime.GOARCH == "ppc64le" {
		return true
	}

	if !cpu.Initialized {
		return false
	}
	if cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ {
		return true
	}

	// ARM CPUs may provide AES and PMULL instructions
	// as well. However, the Go STL does not provide
	// an ARM asm implementation. It provides only an
	// ARM64 implementation.
	if cpu.ARM64.HasAES && cpu.ARM64.HasPMULL {
		return true
	}

	// On S390X, AES-GCM is only enabled when all
	// AES CPU features (CBC, CTR and GHASH / GCM)
	// are available.
	// Ref: https://golang.org/src/crypto/aes/cipher_s390x.go#L39
	if cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR && (cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM) {
		return true
	}
	return false
}
