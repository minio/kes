// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import "testing"

var certpoolFromFileTests = []struct {
	Filename string
}{
	{Filename: "testdata/ca/single.pem"},
}

func TestCertPoolFromFile(t *testing.T) {
	for i, test := range certpoolFromFileTests {
		_, err := CertPoolFromFile(test.Filename)
		if err != nil {
			t.Fatalf("Test %d: failed to load CA certificates: %v", i, err)
		}
	}
}
