// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

//go:build linux && amd64 && fips_strict && !fips
// +build linux,amd64,fips_strict,!fips

package fips

import _ "crypto/tls/fipsonly" // Enfore BoringCrypto

const mode = ModeStrict
