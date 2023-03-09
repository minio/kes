// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import (
	"testing"
)

var readPrivateKeyTests = []struct {
	FilePath   string
	Password   string
	ShouldFail bool
}{
	{FilePath: "testdata/privatekeys/plaintext.pem", Password: ""},                                     // 0
	{FilePath: "testdata/privatekeys/plaintext.pem", Password: "ignored_password"},                     // 1
	{FilePath: "testdata/privatekeys/encrypted.pem", Password: "correct_password"},                     // 2
	{FilePath: "testdata/privatekeys/encrypted.pem", Password: "", ShouldFail: true},                   // 3
	{FilePath: "testdata/privatekeys/encrypted.pem", Password: "incorrect_password", ShouldFail: true}, // 4
}

func TestReadPrivateKey(t *testing.T) {
	for i, test := range readPrivateKeyTests {
		_, err := readPrivateKey(test.FilePath, test.Password)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to read private key %q: %v", i, test.FilePath, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: reading private key %q should have failed", i, test.FilePath)
		}
	}
}

var readCertificateTests = []struct {
	FilePath   string
	ShouldFail bool
}{
	{FilePath: "testdata/certificates/single.pem"},
	{FilePath: "testdata/certificates/with_whitespaces.pem"},
	{FilePath: "testdata/certificates/with_privatekey.pem", ShouldFail: true},
}

func TestReadCertificate(t *testing.T) {
	for i, test := range readCertificateTests {
		_, err := readCertificate(test.FilePath)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to read certificate %q: %v", i, test.FilePath, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: reading certificate %q should have failed", i, test.FilePath)
		}
	}
}

var loadCertPoolTests = []struct {
	CAPath     string
	ShouldFail bool
}{
	{CAPath: "testdata/certificates/single.pem"},
	{CAPath: "testdata/certificates/with_whitespaces.pem"},
	{CAPath: "testdata/certificates/with_privatekey.pem", ShouldFail: true},
	{CAPath: "testdata/certificates", ShouldFail: true},
}

func TestLoadCertPool(t *testing.T) {
	for i, test := range loadCertPoolTests {
		_, err := CertPoolFromFile(test.CAPath)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to load certificate pool %s: %v", i, test.CAPath, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: reading certificate %s should have failed", i, test.CAPath)
		}
	}
}
