// Copyright 2022 - MinIO, Inc. All rights reserved.

// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/kestest"
)

var serverAPIs = []kes.API{
	{Method: http.MethodGet, Path: "/version", MaxBody: 0, Timeout: 15 * time.Second},    // 0
	{Method: http.MethodGet, Path: "/v1/status", MaxBody: 0, Timeout: 15 * time.Second},  // 1
	{Method: http.MethodGet, Path: "/v1/metrics", MaxBody: 0, Timeout: 15 * time.Second}, // 2
	{Method: http.MethodGet, Path: "/v1/api", MaxBody: 0, Timeout: 15 * time.Second},     // 3

	{Method: http.MethodPost, Path: "/v1/key/create/", MaxBody: 0, Timeout: 15 * time.Second},             // 4
	{Method: http.MethodPost, Path: "/v1/key/import/", MaxBody: 1 << 20, Timeout: 15 * time.Second},       // 5
	{Method: http.MethodDelete, Path: "/v1/key/delete/", MaxBody: 0, Timeout: 15 * time.Second},           // 6
	{Method: http.MethodPost, Path: "/v1/key/generate/", MaxBody: 1 << 20, Timeout: 15 * time.Second},     // 7
	{Method: http.MethodPost, Path: "/v1/key/encrypt/", MaxBody: 1 << 20, Timeout: 15 * time.Second},      // 8
	{Method: http.MethodPost, Path: "/v1/key/decrypt/", MaxBody: 1 << 20, Timeout: 15 * time.Second},      // 9
	{Method: http.MethodPost, Path: "/v1/key/bulk/decrypt/", MaxBody: 1 << 20, Timeout: 15 * time.Second}, // 10
	{Method: http.MethodGet, Path: "/v1/key/list/", MaxBody: 0, Timeout: 15 * time.Second},                // 11

	{Method: http.MethodGet, Path: "/v1/policy/describe/", MaxBody: 0, Timeout: 15 * time.Second},     // 12
	{Method: http.MethodPost, Path: "/v1/policy/assign/", MaxBody: 1024, Timeout: 15 * time.Second},   // 13
	{Method: http.MethodGet, Path: "/v1/policy/read/", MaxBody: 0, Timeout: 15 * time.Second},         // 14
	{Method: http.MethodPost, Path: "/v1/policy/write/", MaxBody: 1 << 20, Timeout: 15 * time.Second}, // 15
	{Method: http.MethodGet, Path: "/v1/policy/list/", MaxBody: 0, Timeout: 15 * time.Second},         // 16
	{Method: http.MethodDelete, Path: "/v1/policy/delete/", MaxBody: 0, Timeout: 15 * time.Second},    // 17

	{Method: http.MethodGet, Path: "/v1/identity/describe/", MaxBody: 0, Timeout: 15 * time.Second},     // 18
	{Method: http.MethodGet, Path: "/v1/identity/self/describe", MaxBody: 0, Timeout: 15 * time.Second}, // 19
	{Method: http.MethodGet, Path: "/v1/identity/list/", MaxBody: 0, Timeout: 15 * time.Second},         // 20
	{Method: http.MethodDelete, Path: "/v1/identity/delete/", MaxBody: 0, Timeout: 15 * time.Second},    // 21

	{Method: http.MethodGet, Path: "/v1/log/error", MaxBody: 0, Timeout: 0}, // 22
	{Method: http.MethodGet, Path: "/v1/log/audit", MaxBody: 0, Timeout: 0}, // 23

	{Method: http.MethodPost, Path: "/v1/enclave/create/", MaxBody: 1 << 20, Timeout: 15 * time.Second}, // 24
	{Method: http.MethodDelete, Path: "/v1/enclave/delete/", MaxBody: 0, Timeout: 15 * time.Second},     // 25

	{Method: http.MethodPost, Path: "/v1/sys/seal", MaxBody: 0, Timeout: 15 * time.Second}, // 26
}

func TestAPIs(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()

	apis, err := client.APIs(ctx)
	if err != nil {
		t.Fatalf("Failed fetch server APIs: %v", err)
	}
	if len(apis) != len(serverAPIs) {
		t.Fatalf("API mismatch: got len '%d' - want len '%d'", len(apis), len(serverAPIs))
	}
	for i := range apis {
		if apis[i].Method != serverAPIs[i].Method {
			t.Fatalf("API %d: method mismatch: got '%s' - want '%s'", i, apis[i].Method, serverAPIs[i].Method)
		}
		if apis[i].Path != serverAPIs[i].Path {
			t.Fatalf("API %d: path mismatch: got '%s' - want '%s'", i, apis[i].Path, serverAPIs[i].Path)
		}
		if apis[i].MaxBody != serverAPIs[i].MaxBody {
			t.Fatalf("API %d: max body mismatch: got '%d' - want '%d'", i, apis[i].MaxBody, serverAPIs[i].MaxBody)
		}
		if apis[i].Timeout != serverAPIs[i].Timeout {
			t.Fatalf("API %d: timeout mismatch: got '%v' - want '%v'", i, apis[i].Timeout, serverAPIs[i].Timeout)
		}
	}
}

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

var decryptKeyTests = []struct {
	Ciphertext []byte
	Plaintext  []byte
	Context    []byte
	ShouldFail bool
}{
	{
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiQkpDU2FRZ1MrMUovZ3ZhcWZNaXJYUT09Iiwibm9uY2UiOiJHZkllRHdSdjByRDBIYncrIiwiYnl0ZXMiOiIvNndhelRQbnREMHhra0w5RWFGWjduK0s5SEJhem5YaDlKYjcifQ=="),
		Plaintext:  []byte("Hello World"),
		Context:    nil,
	},
	{
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiYVN0OExGZWE2UUlFNVhhaEpTQ0w0Zz09Iiwibm9uY2UiOiJISjYyYndDcW1vMWVncHoxIiwiYnl0ZXMiOiJ1c291ZjhTb0Z5R1dybStOV0ZUQXFnPT0ifQ=="),
		Plaintext:  nil,
		Context:    make([]byte, 32),
	},
	{
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2Ijoia3dLalZpcTBHSXpnMWJVcDM3QVNwZz09Iiwibm9uY2UiOiJ3Q0lJZEorcys3NTdGNjZFIiwiYnl0ZXMiOiIwYkZDSEY3NFUwZ29CT2w2d1lTaGE2K3FFV2FtNVZYYllxTW4ifQ=="),
		Plaintext:  []byte("Hello World"),
		Context:    make([]byte, 32),
	},
}

func TestDecryptKey(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()

	const KeyName = "my-key"
	const KeyValue = "pQLPe6/f87AMSItvZzEbrxYdRUzmM81ziXF95HOFE4Y="
	if err := client.ImportKey(ctx, KeyName, mustDecodeB64(KeyValue)); err != nil {
		t.Fatalf("Failed to create %q: %v", KeyName, err)
	}
	for i, test := range decryptKeyTests {
		plaintext, err := client.Decrypt(ctx, KeyName, test.Ciphertext, test.Context)
		if test.ShouldFail {
			if err == nil {
				t.Fatalf("Test %d: should fail but succeeded", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
		}
		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: failed to decrypt ciphertext: got '%x' - want '%x'", i, plaintext, test.Plaintext)
		}
	}
}

var decryptAllKeyTests = []struct {
	Ciphertexts []kes.CCP
	Plaintexts  []kes.PCP
	ShouldFail  bool
}{
	{ // 0
		Ciphertexts: []kes.CCP{
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiQkpDU2FRZ1MrMUovZ3ZhcWZNaXJYUT09Iiwibm9uY2UiOiJHZkllRHdSdjByRDBIYncrIiwiYnl0ZXMiOiIvNndhelRQbnREMHhra0w5RWFGWjduK0s5SEJhem5YaDlKYjcifQ==")},
		},
		Plaintexts: []kes.PCP{
			{Plaintext: []byte("Hello World")},
		},
	},
	{ // 1
		Ciphertexts: []kes.CCP{
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiQkpDU2FRZ1MrMUovZ3ZhcWZNaXJYUT09Iiwibm9uY2UiOiJHZkllRHdSdjByRDBIYncrIiwiYnl0ZXMiOiIvNndhelRQbnREMHhra0w5RWFGWjduK0s5SEJhem5YaDlKYjcifQ==")},
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiR3pFcFI0am1JMWRWTzJsdXZvdG9xQT09Iiwibm9uY2UiOiJCV2c1eE54eU4yck9sLzV3IiwiYnl0ZXMiOiJmVXlycTI1Q3VDeEp4TW5XOXVZSSsrSjVsVzdGbVFtcmZpdEoifQ=="), Context: []byte("Hello World Context")},
		},
		Plaintexts: []kes.PCP{
			{Plaintext: []byte("Hello World")},
			{Plaintext: []byte("Hello World"), Context: []byte("Hello World Context")},
		},
	},
	{ // 2
		Ciphertexts: []kes.CCP{
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiQkpDU2FRZ1MrMUovZ3ZhcWZNaXJYUT09Iiwibm9uY2UiOiJHZkllRHdSdjByRDBIYncrIiwiYnl0ZXMiOiIvNndhelRQbnREMHhra0w5RWFGWjduK0s5SEJhem5YaDlKYjcifQ==")},
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiR3pFcFI0am1JMWRWTzJsdXZvdG9xQT09Iiwibm9uY2UiOiJCV2c1eE54eU4yck9sLzV3IiwiYnl0ZXMiOiJmVXlycTI1Q3VDeEp4TW5XOXVZSSsrSjVsVzdGbVFtcmZpdEoifQ=="), Context: []byte("Hello World Context")},
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiRDc5M3VKOEtuUjlrUjBzUm9QNGt5Zz09Iiwibm9uY2UiOiJOQ245dkFqQUhla0QyQW9OIiwiYnl0ZXMiOiJrZGZVRjErMVIvSEFXRkhrU3RjRGdkOHlya3hSUmYvNFV4ZmtPTGxiWjZJM0IxWml3MG0yUjZkM2JZalE3NVZ6In0="), Context: mustDecodeB64("3L+XLd07zRgH+JT/TDGj5Q==")},
		},
		Plaintexts: []kes.PCP{
			{Plaintext: []byte("Hello World")},
			{Plaintext: []byte("Hello World"), Context: []byte("Hello World Context")},
			{Plaintext: mustDecodeB64("20p8/WDxkN2ekJWmOpabC48urRMnhfbAUOUB6TvRAN8="), Context: mustDecodeB64("3L+XLd07zRgH+JT/TDGj5Q==")},
		},
	},

	{ // 3
		Ciphertexts: []kes.CCP{
			{Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaWQiOiI2MmNmMjEzMDY2OTI3MmYzOWY3ZGU2MDU4Y2YzNzEyMyIsIml2IjoiR3pFcFI0am1JMWRWTzJsdXZvdG9xQT09Iiwibm9uY2UiOiJCV2c1eE54eU4yck9sLzV3IiwiYnl0ZXMiOiJmVXlycTI1Q3VDeEp4TW5XOXVZSSsrSjVsVzdGbVFtcmZpdEoifQ==")},
		},
		ShouldFail: true, // Wrong context
	},
}

func TestDecryptKeyAll(t *testing.T) {
	ctx, cancel := testingContext(t)
	defer cancel()

	server := kestest.NewServer()
	defer server.Close()

	client := server.Client()

	const KeyName = "my-key"
	const KeyValue = "pQLPe6/f87AMSItvZzEbrxYdRUzmM81ziXF95HOFE4Y="
	if err := client.ImportKey(ctx, KeyName, mustDecodeB64(KeyValue)); err != nil {
		t.Fatalf("Failed to create %q: %v", KeyName, err)
	}

	for i, test := range decryptAllKeyTests {
		plaintexts, err := client.DecryptAll(ctx, KeyName, test.Ciphertexts...)
		if test.ShouldFail {
			if err == nil {
				t.Fatalf("Test %d: should fail but succeeded", i)
			}
			continue
		}
		if err != nil {
			t.Fatalf("Test %d: failed to decrypt ciphertexts: %v", i, err)
		}
		if len(plaintexts) != len(test.Plaintexts) {
			t.Fatalf("Test %d: plaintext mismatch: got len '%d' - want len '%d'", i, len(plaintexts), len(test.Plaintexts))
		}
		for j := range test.Plaintexts {
			if !bytes.Equal(plaintexts[j].Plaintext, test.Plaintexts[j].Plaintext) {
				t.Fatalf("Test %d: %d-nth plaintext mismatch: got '%x' - want '%x'", i, j, plaintexts[j].Plaintext, test.Plaintexts[j].Plaintext)
			}
			if !bytes.Equal(plaintexts[j].Context, test.Plaintexts[j].Context) {
				t.Fatalf("Test %d: %d-nth context mismatch: got '%x' - want '%x'", i, j, plaintexts[j].Context, test.Plaintexts[j].Context)
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

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
