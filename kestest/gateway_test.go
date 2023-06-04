// Copyright 2022 - MinIO, Inc. All rights reserved.

// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"testing"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/kestest"
)

const ranStringLength = 8

var gatewayAPIs = map[string]struct {
	Method  string
	MaxBody int64
	Timeout time.Duration
}{
	"/version":    {Method: http.MethodGet, MaxBody: 0, Timeout: 10 * time.Second},
	"/v1/ready":   {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/status":  {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/metrics": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/api":     {Method: http.MethodGet, MaxBody: 0, Timeout: 10 * time.Second},

	"/v1/key/create/":   {Method: http.MethodPut, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/key/import/":   {Method: http.MethodPut, MaxBody: int64(1 * mem.KiB), Timeout: 15 * time.Second},
	"/v1/key/describe/": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/key/list/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/key/delete/":   {Method: http.MethodDelete, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/key/generate/": {Method: http.MethodPut, MaxBody: 1 << 20, Timeout: 15 * time.Second},
	"/v1/key/encrypt/":  {Method: http.MethodPut, MaxBody: 1 << 20, Timeout: 15 * time.Second},
	"/v1/key/decrypt/":  {Method: http.MethodPut, MaxBody: 1 << 20, Timeout: 15 * time.Second},

	"/v1/policy/describe/": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/policy/read/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/policy/list/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},

	"/v1/identity/describe/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/identity/self/describe": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
	"/v1/identity/list/":         {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},

	"/v1/log/error": {Method: http.MethodGet, MaxBody: 0, Timeout: 0},
	"/v1/log/audit": {Method: http.MethodGet, MaxBody: 0, Timeout: 0},
}

func testMetrics(ctx context.Context, store edge.KeyStore, t *testing.T) {
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	metric, err := client.Metrics(ctx)
	if err != nil {
		t.Fatalf("Failed fetch server metrics: %v", err)
	}
	if n := metric.RequestOK + metric.RequestErr + metric.RequestFail; n != metric.RequestN() {
		t.Fatalf("metrics request count differs: got %d - want %d", n, metric.RequestN())
	}
	if metric.CPUs == 0 {
		t.Fatalf("metrics contains no number of CPUs")
	}
	if metric.HeapAlloc == 0 {
		t.Fatalf("metrics contains no heap allocations")
	}
	if metric.HeapObjects == 0 {
		t.Fatalf("metrics contains no heap objects")
	}
	if metric.StackAlloc == 0 {
		t.Fatalf("metrics contains no stack allocations")
	}
}

func testAPIs(ctx context.Context, store edge.KeyStore, t *testing.T) {
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	apis, err := client.APIs(ctx)
	if err != nil {
		t.Fatalf("Failed fetch server APIs: %v", err)
	}
	if len(apis) != len(gatewayAPIs) {
		t.Fatalf("API mismatch: got len '%d' - want len '%d'", len(apis), len(gatewayAPIs))
	}
	for i := range apis {
		api, ok := gatewayAPIs[apis[i].Path]
		if !ok {
			t.Fatalf("API '%s': API not found", apis[i].Path)
		}
		if apis[i].Method != api.Method {
			t.Fatalf("API '%s': method mismatch: got '%s' - want '%s'", apis[i].Path, apis[i].Method, api.Method)
		}
		if apis[i].MaxBody != api.MaxBody {
			t.Fatalf("API '%s': max body mismatch: got '%d' - want '%d'", apis[i].Path, apis[i].MaxBody, api.MaxBody)
		}
		if apis[i].Timeout != api.Timeout {
			t.Fatalf("API '%s': timeout mismatch: got '%v' - want '%v'", apis[i].Path, apis[i].Timeout, api.Timeout)
		}
	}
}

var createKeyTests = []struct {
	Name       string
	ShouldFail bool
	Err        error
}{
	{ // 0
		Name: "kestest",
	},
	{ // 1
		Name:       "kestest",
		ShouldFail: true,
		Err:        kes.ErrKeyExists,
	},
}

func testCreateKey(ctx context.Context, store edge.KeyStore, t *testing.T, seed string) {
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	defer clean(ctx, client, t, seed)

	for i, test := range createKeyTests {
		err := client.CreateKey(ctx, fmt.Sprintf("%s-%s", test.Name, seed))
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
	{ // 0
		Name: "kestest",
		Key:  make([]byte, 32),
	},
	{ // 1
		Name:       "kestest",
		Key:        make([]byte, 32),
		ShouldFail: true,
		Err:        kes.ErrKeyExists,
	},

	{ // 2
		Name:       "fail-key",
		Key:        make([]byte, 0),
		ShouldFail: true,
	},
	{ // 3
		Name:       "fail-key2",
		Key:        make([]byte, 1<<20),
		ShouldFail: true,
	},
}

func testImportKey(ctx context.Context, store edge.KeyStore, t *testing.T, seed string) {
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	defer clean(ctx, client, t, seed)

	for i, test := range importKeyTests {
		err := client.ImportKey(ctx, fmt.Sprintf("%s-%s", test.Name, seed), &kes.ImportKeyRequest{Key: test.Key})
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

func testGenerateKey(ctx context.Context, store edge.KeyStore, t *testing.T, seed string) {
	keyName := fmt.Sprintf("kestest-%s", seed)

	server := kestest.NewEdgeServer(store)
	defer server.Stop()

	client := server.Client()

	defer clean(ctx, client, t, seed)
	if err := client.CreateKey(ctx, keyName); err != nil {
		t.Fatalf("Failed to create %q: %v", keyName, err)
	}
	for i, test := range generateKeyTests {
		dek, err := client.GenerateKey(ctx, keyName, test.Context)
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
			plaintext, err := client.Decrypt(ctx, keyName, dek.Ciphertext, test.Context)
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

func testEncryptKey(ctx context.Context, store edge.KeyStore, t *testing.T, seed string) {
	keyName := fmt.Sprintf("kestest-%s", seed)
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	defer clean(ctx, client, t, seed)

	if err := client.CreateKey(ctx, keyName); err != nil {
		t.Fatalf("Failed to create %q: %v", keyName, err)
	}
	for i, test := range encryptKeyTests {
		ciphertext, err := client.Encrypt(ctx, keyName, test.Plaintext, test.Context)
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
			plaintext, err := client.Decrypt(ctx, keyName, ciphertext, test.Context)
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

func testDecryptKey(ctx context.Context, store edge.KeyStore, t *testing.T, seed string) {
	keyName := fmt.Sprintf("kestest-%s", seed)
	server := kestest.NewEdgeServer(store)
	defer server.Stop()
	client := server.Client()

	defer clean(ctx, client, t, seed)

	const KeyValue = "pQLPe6/f87AMSItvZzEbrxYdRUzmM81ziXF95HOFE4Y="
	if err := client.ImportKey(ctx, keyName, &kes.ImportKeyRequest{Key: mustDecodeB64(KeyValue)}); err != nil {
		t.Fatalf("Failed to create %q: %v", keyName, err)
	}
	for i, test := range decryptKeyTests {
		plaintext, err := client.Decrypt(ctx, keyName, test.Ciphertext, test.Context)
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

var getPolicyTests = []struct {
	Name   string
	Policy *kes.Policy
}{
	{Name: "my-policy", Policy: &kes.Policy{}},
	{
		Name: "my-policy2",
		Policy: &kes.Policy{
			Allow: map[string]kes.Rule{
				"/v1/key/create/*":   {},
				"/v1/key/generate/*": {},
			},
		},
	},
	{
		Name: "my-policy2",
		Policy: &kes.Policy{
			Allow: map[string]kes.Rule{
				"/v1/key/create/*":   {},
				"/v1/key/generate/*": {},
			},
			Deny: map[string]kes.Rule{
				"/v1/key/create/my-key2": {},
			},
		},
	},
}

func testDescribePolicy(ctx context.Context, store edge.KeyStore, t *testing.T) {
	for i, test := range getPolicyTests {
		t.Run(fmt.Sprintf("Test %d", i), func(t *testing.T) {
			server := kestest.NewEdgeServer(store)
			defer server.Stop()

			server.AddPolicy(test.Name, test.Policy)
			client := server.Client()

			info, err := client.DescribePolicy(ctx, test.Name)
			if err != nil {
				t.Fatalf("Test %d: failed to describe policy: %v", i, err)
			}
			if info.Name != test.Name {
				t.Fatalf("Test %d: policy name mismatch: got '%s' - want '%s'", i, info.Name, test.Name)
			}
			if info.CreatedAt.IsZero() {
				t.Fatalf("Test %d: created_at timestamp not set", i)
			}
			if info.CreatedBy.IsUnknown() {
				t.Fatalf("Test %d: created_by identity not set", i)
			}
		})
	}
}

func testGetPolicy(ctx context.Context, store edge.KeyStore, t *testing.T) {
	for i, test := range getPolicyTests {
		t.Run(fmt.Sprintf("Test %d", i), func(t *testing.T) {
			server := kestest.NewEdgeServer(store)
			defer server.Stop()

			server.AddPolicy(test.Name, test.Policy)
			client := server.Client()

			policy, err := client.GetPolicy(ctx, test.Name)
			if err != nil {
				t.Fatalf("Test %d: failed to describe policy: %v", i, err)
			}
			if policy.CreatedAt.IsZero() {
				t.Fatalf("Test %d: created_at timestamp not set", i)
			}
			if policy.CreatedBy.IsUnknown() {
				t.Fatalf("Test %d: created_by identity not set", i)
			}

			if len(policy.Allow) != len(test.Policy.Allow) {
				t.Fatalf("Test %d: allow policy mismatch: got len %d - want len %d", i, len(policy.Allow), len(test.Policy.Allow))
			}
			if !equal(test.Policy.Allow, policy.Allow) {
				t.Fatalf("Test %d: allow policy mismatch: got '%v' - want '%v'", i, policy.Allow, test.Policy.Allow)
			}
			if len(policy.Deny) != len(test.Policy.Deny) {
				t.Fatalf("Test %d: deny policy mismatch: got len %d - want len %d", i, len(policy.Deny), len(test.Policy.Deny))
			}
			if !equal(test.Policy.Deny, policy.Deny) {
				t.Fatalf("Test %d: deny policy mismatch: got '%v' - want '%v'", i, policy.Deny, test.Policy.Deny)
			}
		})
	}
}

var selfDescribeTests = []struct {
	Policy kes.Policy
}{
	{ // 0
		Policy: kes.Policy{},
	},
	{ // 1
		Policy: kes.Policy{Allow: map[string]kes.Rule{}, Deny: map[string]kes.Rule{}},
	},
	{ // 2
		Policy: kes.Policy{
			Allow: map[string]kes.Rule{
				"/v1/key/create/my-key-*":   {},
				"/v1/key/generate/my-key-*": {},
				"/v1/key/decrypt/my-key-*":  {},
				"/v1/key/delete/my-key-*":   {},
			},
			Deny: map[string]kes.Rule{
				"/v1/key/delete/my-key-prod-*": {},
			},
		},
	},
}

func testSelfDescribe(ctx context.Context, store edge.KeyStore, t *testing.T) {
	server := kestest.NewEdgeServer(store)
	defer server.Stop()

	client := server.Client()
	info, policy, err := client.DescribeSelf(ctx)
	if err != nil {
		t.Fatalf("Failed to self-describe client: %v", err)
	}
	// if !info.IsAdmin {
	// 	t.Fatalf("Identity hasn't admin privileges: got '%s' - want '%s'", info.Identity, server.Policy().Admin())
	// }
	// if admin := server.Policy().Admin(); info.Identity != admin {
	// 	t.Fatalf("Identity hasn't admin privileges: got '%s' - want '%s'", info.Identity, server.Policy().Admin())
	// }
	if len(policy.Allow) != 0 || len(policy.Deny) != 0 {
		t.Fatalf("Admin identity has a policy: %v", policy)
	}

	for i, test := range selfDescribeTests {
		apiKey, err := kes.GenerateAPIKey(nil)
		if err != nil {
			t.Fatalf("Test %d: failed to generate API key: %v", i, err)
		}
		cert, err := kes.GenerateCertificate(apiKey)
		if err != nil {
			t.Fatalf("Test %d: failed to generate client certificate: %v", i, err)
		}
		client = kes.NewClientWithConfig(server.URL(), &tls.Config{
			RootCAs:      server.CAs(),
			Certificates: []tls.Certificate{cert},
		})
		policyName := "Test-" + strconv.Itoa(i)
		server.AddPolicy(policyName, &test.Policy, apiKey.Identity())

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

func equal[T any](a, b map[string]T) bool {
	if len(a) != len(b) {
		return false
	}
	for path := range a {
		if _, ok := b[path]; !ok {
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

func clean(ctx context.Context, client *kes.Client, t *testing.T, seed string) {
	iter := kes.ListIter[string]{
		NextFunc: client.ListKeys,
	}

	var names []string
	for next, err := iter.Next(ctx); err != io.EOF; next, err = iter.Next(ctx) {
		if err != nil {
			t.Errorf("Cleanup: failed to list keys: %v", err)
		}
		names = append(names, next)
	}
	for _, name := range names {
		if err := client.DeleteKey(ctx, name); err != nil && !errors.Is(err, kes.ErrKeyNotFound) {
			t.Errorf("Cleanup: failed to delete '%s': %v", name, err)
		}
	}
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
