// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys_test

import (
	"testing"

	"github.com/minio/kes/internal/sys"
)

var verifyEnclaveNameTests = []struct {
	Name  string
	Valid bool
}{
	{Name: "default", Valid: true},      // 0
	{Name: "0271283", Valid: true},      // 1
	{Name: "DeFaulT_0", Valid: true},    // 2
	{Name: "enclave-01_A", Valid: true}, // 3

	{Name: ""},                // 4
	{Name: "/default"},        // 5
	{Name: "default enclave"}, // 6
	{Name: "./"},              // 7
	{Name: ".."},              // 8
	{Name: "/"},               // 9
	{Name: "привет"},          // 10
	{Name: "你"},               // 11
	{Name: "tenant[1]"},       // 12
}

func TestVerifyEnclaveName(t *testing.T) {
	for i, test := range verifyEnclaveNameTests {
		err := sys.VerifyEnclaveName(test.Name)
		if err == nil && !test.Valid {
			t.Fatalf("Test %d: name verification passed but '%s' is an invalid enclave name", i, test.Name)
		}
		if err != nil && test.Valid {
			t.Fatalf("Test %d: name verification failed: %v", i, err)
		}
	}
}
