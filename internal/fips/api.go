// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fips

// Enabled indicates whether cryptographic primitives,
// like AES or SHA-256, are implemented using a FIPS 140
// certified module.
//
// If FIPS-140 is enabled no non-NIST/FIPS approved
// primitives must be used.
const Enabled = enabled
