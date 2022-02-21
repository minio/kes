// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/minio/kes"
	"github.com/minio/kes/kestest"
)

var createKeyTests = []struct {
	Name       string
	ShouldFail bool
	Err        error
}{
	{Name: "my-key"},
	{Name: "my-key", ShouldFail: true, Err: kes.ErrKeyExists},
}

func TestCreateKey(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()
	for i, test := range createKeyTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should fail but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to create key: %v", i, err)
		}
		if test.ShouldFail && test.Err != nil && err != test.Err {
			t.Fatalf("Test %d: expected to fail with: '%v' - got: '%v'", i, test.Err, err)
		}
	}
}

var importKeyTests = []struct {
	Name       string
	Key        []byte
	ShouldFail bool
	Err        error
}{
	{Name: "my-key", Key: make([]byte, 32)},
	{Name: "my-key", Key: make([]byte, 32), ShouldFail: true, Err: kes.ErrKeyExists},

	{Name: "fail-key", Key: make([]byte, 0), ShouldFail: true},
	{Name: "fail-key2", Key: make([]byte, 1<<20), ShouldFail: true},
}

func TestImportKey(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()
	for i, test := range importKeyTests {
		err := client.ImportKey(ctx, test.Name, test.Key)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should fail but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to import key: %v", i, err)
		}
		if test.ShouldFail && test.Err != nil && err != test.Err {
			t.Fatalf("Test %d: expected to fail with: '%v' - got: '%v'", i, test.Err, err)
		}
	}
}

var generateKeyTests = []struct {
	Context    []byte
	ShouldFail bool
	Err        error
}{
	{Context: make([]byte, 0)},
	{Context: []byte("Hello World")},
	{Context: make([]byte, 1<<20), ShouldFail: true},
}

func TestGenerateKey(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()

	const KeyName = "my-key"
	if err := client.CreateKey(ctx, KeyName); err != nil {
		t.Fatalf("Failed to create %q: %v", KeyName, err)
	}
	for i, test := range generateKeyTests {
		dek, err := client.GenerateKey(ctx, KeyName, test.Context)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should fail but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to generate DEK: %v", i, err)
		}
		if test.ShouldFail && test.Err != nil && err != test.Err {
			t.Fatalf("Test %d: expected to fail with: '%v' - got: '%v'", i, test.Err, err)
		}

		if !test.ShouldFail {
			plaintext, err := client.Decrypt(ctx, KeyName, dek.Ciphertext, test.Context)
			if err != nil {
				t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
			}
			if !bytes.Equal(dek.Plaintext, plaintext) {
				t.Fatalf("Test %d: decryption failed: got %x - want %x", i, plaintext, dek.Plaintext)
			}
		}
	}
}

var encryptKeyTests = []struct {
	Plaintext  []byte
	Context    []byte
	ShouldFail bool
	Err        error
}{
	{Plaintext: []byte("Hello World"), Context: make([]byte, 0)},
	{Plaintext: []byte("Hello World"), Context: make([]byte, 32)},

	{Plaintext: make([]byte, 1<<20), Context: make([]byte, 0), ShouldFail: true},
	{Plaintext: make([]byte, 0), Context: make([]byte, 1<<20), ShouldFail: true},
	{Plaintext: make([]byte, 512*1024), Context: make([]byte, 512*1024), ShouldFail: true},
}

func TestEncryptKey(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()

	const KeyName = "my-key"
	if err := client.CreateKey(ctx, KeyName); err != nil {
		t.Fatalf("Failed to create %q: %v", KeyName, err)
	}
	for i, test := range encryptKeyTests {
		ciphertext, err := client.Encrypt(ctx, KeyName, test.Plaintext, test.Context)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should fail but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to encrypt plaintext: %v", i, err)
		}
		if test.ShouldFail && test.Err != nil && err != test.Err {
			t.Fatalf("Test %d: expected to fail with: '%v' - got: '%v'", i, test.Err, err)
		}

		if !test.ShouldFail {
			plaintext, err := client.Decrypt(ctx, KeyName, ciphertext, test.Context)
			if err != nil {
				t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
			}
			if !bytes.Equal(test.Plaintext, plaintext) {
				t.Fatalf("Test %d: decryption failed: got %x - want %x", i, plaintext, test.Plaintext)
			}
		}
	}
}

var setPolicyTests = []struct {
	Name       string
	Policy     *kes.Policy
	ShouldFail bool
	Err        error
}{
	{Name: "my-policy", Policy: &kes.Policy{}},
	{
		Name: "my-policy2",
		Policy: &kes.Policy{
			Allow: []string{"/v1/key/create/*", "/v1/key/generate/*"},
		},
	},
	{
		Name: "my-policy2",
		Policy: &kes.Policy{
			Allow: []string{"/v1/key/create/*", "/v1/key/generate/*"},
			Deny:  []string{"/v1/key/create/my-key2"},
		},
	},
	{
		Name: "fail-policy",
		Policy: &kes.Policy{
			Allow: []string{strings.Repeat("a", 1<<20)},
		},
		ShouldFail: true,
	},
}

func TestSetPolicy(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()
	for i, test := range setPolicyTests {
		err := client.SetPolicy(ctx, test.Name, test.Policy)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should fail but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to set policy: %v", i, err)
		}
		if test.ShouldFail && test.Err != nil && err != test.Err {
			t.Fatalf("Test %d: expected to fail with: '%v' - got: '%v'", i, test.Err, err)
		}
	}
}

func testingContext(t *testing.T) (context.Context, context.CancelFunc) {
	deadline, ok := t.Deadline()
	if ok {
		return context.WithDeadline(context.Background(), deadline)
	}
	return context.WithCancel(context.Background())
}
