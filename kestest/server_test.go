// Copyright 2022 - MinIO, Inc. All rights reserved.

// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"sort"
	"strconv"
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

var selfDescribeTests = []struct {
	Policy kes.Policy
}{
	{ // 0
		Policy: kes.Policy{},
	},
	{ // 1
		Policy: kes.Policy{Allow: []string{}, Deny: []string{}},
	},
	{ // 2
		Policy: kes.Policy{
			Allow: []string{
				"/v1/key/create/my-key-*",
				"/v1/key/generate/my-key-*",
				"/v1/key/decrypt/my-key-*",
				"/v1/key/delete/my-key-*",
			},
			Deny: []string{
				"/v1/key/delete/my-key-prod-*",
			},
		},
	},
}

func TestSelfDescribe(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()
	info, policy, err := client.DescribeSelf(ctx)
	if err != nil {
		t.Fatalf("Failed to self-describe client: %v", err)
	}
	if !info.IsAdmin {
		t.Fatalf("Identity hasn't admin privileges: got '%s' - want '%s'", info.Identity, server.Policy().Admin())
	}
	if admin := server.Policy().Admin(); info.Identity != admin {
		t.Fatalf("Identity hasn't admin privileges: got '%s' - want '%s'", info.Identity, server.Policy().Admin())
	}
	if len(policy.Allow) != 0 || len(policy.Deny) != 0 {
		t.Fatalf("Admin identity has a policy: %v", policy)
	}

	for i, test := range selfDescribeTests {
		cert := server.IssueClientCertificate("self-describe test")
		client = kes.NewClientWithConfig(server.URL, &tls.Config{
			RootCAs:      server.CAs(),
			Certificates: []tls.Certificate{cert},
		})
		policyName := "Test-" + strconv.Itoa(i)
		server.Policy().Add(policyName, &test.Policy)
		server.Policy().Assign(policyName, kestest.Identify(&cert))

		info, policy, err = client.DescribeSelf(ctx)
		if err != nil {
			t.Fatalf("Test %d: failed to self-describe client: %v", i, err)
		}
		if info.IsAdmin {
			t.Fatalf("Test %d: identity has admin privileges", i)
		}
		if info.Policy != policyName {
			t.Fatalf("Test %d: policy name mismatch: got '%s' - want '%s'", i, info.Policy, policyName)
		}
		if id := kestest.Identify(&cert); info.Identity != id {
			t.Fatalf("Test %d: identity mismatch: got '%v' - want '%v'", i, info.Identity, id)
		}
		if !equal(policy.Allow, test.Policy.Allow) {
			t.Fatalf("Test %d: allow policy mismatch: got '%v' - want '%v'", i, policy.Allow, test.Policy.Allow)
		}
		if !equal(policy.Deny, test.Policy.Deny) {
			t.Fatalf("Test %d: deny policy mismatch: got '%v' - want '%v'", i, policy.Deny, test.Policy.Deny)
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

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	sort.Strings(a)
	sort.Strings(b)
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
