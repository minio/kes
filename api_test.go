// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"aead.dev/mem"
	"github.com/minio/kms-go/kes"
)

func TestImportKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)

	const name = "my-key"
	for i, test := range importKeyTests {
		name := name + "-" + strconv.Itoa(i)
		err := client.ImportKey(ctx, name, &kes.ImportKeyRequest{
			Key:    test.Key,
			Cipher: test.Cipher,
		})
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, name, err)
		}
	}
}

func TestAPI(t *testing.T) {
	t.Parallel()

	t.Run("v1/metrics", testMetrics)
	t.Run("v1/api", testListAPIDefaults)
	t.Run("v1/status", testStatus)
	t.Run("v1/key/create", testCreateKey)
	t.Run("v1/key/delete", testDeleteKey)
	t.Run("v1/key/import", testImportKey)
	t.Run("v1/key/describe", testDescribeKey)
	t.Run("v1/key/generate", testGenerateKey)
	t.Run("v1/key/hmac", testHMAC)
	t.Run("v1/key/encrypt", testEncryptDecryptKey) // also tests decryption
	t.Run("v1/key/list", testListKeys)
	t.Run("v1/identity/describe", testDescribeIdentity)
	t.Run("v1/identity/list", testListIdentities)
	t.Run("v1/identity/self/describe", testSelfDescribeIdentity)
	t.Run("v1/policy/describe", testDescribePolicy)
	t.Run("v1/policy/read", testReadPolicy)
	t.Run("v1/policy/list", testListPolicies)
}

func testMetrics(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
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

func testStatus(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	stat, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Failed to fetch status information: %v", err)
	}
	if stat.Arch != runtime.GOARCH {
		t.Fatalf("Invalid status: got '%s' - want '%s'", stat.Arch, runtime.GOARCH)
	}
	if stat.OS != runtime.GOOS {
		t.Fatalf("Invalid status: got '%s' - want '%s'", stat.OS, runtime.GOOS)
	}
	if stat.StackAlloc == 0 {
		t.Fatal("Invalid status: allocated stack memory cannot be 0")
	}
	if stat.HeapAlloc == 0 {
		t.Fatal("Invalid status: allocated heap memory cannot be 0")
	}
}

func testListAPIDefaults(t *testing.T) {
	defaults := map[string]struct {
		Method  string
		MaxBody mem.Size
		Timeout time.Duration
	}{
		"/version":    {Method: http.MethodGet, MaxBody: 0, Timeout: 10 * time.Second},
		"/v1/ready":   {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/status":  {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/metrics": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/api":     {Method: http.MethodGet, MaxBody: 0, Timeout: 10 * time.Second},

		"/v1/key/create/":   {Method: http.MethodPut, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/key/import/":   {Method: http.MethodPut, MaxBody: 1 * mem.MB, Timeout: 15 * time.Second},
		"/v1/key/describe/": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/key/list/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/key/delete/":   {Method: http.MethodDelete, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/key/generate/": {Method: http.MethodPut, MaxBody: 1 * mem.MB, Timeout: 15 * time.Second},
		"/v1/key/encrypt/":  {Method: http.MethodPut, MaxBody: 1 * mem.MB, Timeout: 15 * time.Second},
		"/v1/key/decrypt/":  {Method: http.MethodPut, MaxBody: 1 * mem.MB, Timeout: 15 * time.Second},
		"/v1/key/hmac/":     {Method: http.MethodPut, MaxBody: 1 * mem.MB, Timeout: 15 * time.Second},

		"/v1/policy/describe/": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/policy/read/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/policy/list/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},

		"/v1/identity/describe/":     {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/identity/self/describe": {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},
		"/v1/identity/list/":         {Method: http.MethodGet, MaxBody: 0, Timeout: 15 * time.Second},

		"/v1/log/error": {Method: http.MethodGet, MaxBody: 0, Timeout: 0},
		"/v1/log/audit": {Method: http.MethodGet, MaxBody: 0, Timeout: 0},
	}

	t.Parallel()
	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	routes, err := client.APIs(ctx)
	if err != nil {
		t.Fatalf("Failed fetch server APIs: %v", err)
	}
	if len(routes) != len(defaults) {
		t.Fatalf("Routes mismatch: got len '%d' - want len '%d'", len(routes), len(defaults))
	}
	for i := range routes {
		api, ok := defaults[routes[i].Path]
		if !ok {
			t.Fatalf("Route '%s': not found", routes[i].Path)
		}
		if routes[i].Method != api.Method {
			t.Fatalf("Route '%s': method mismatch: got '%s' - want '%s'", routes[i].Path, routes[i].Method, api.Method)
		}
		if routes[i].MaxBody != int64(api.MaxBody) {
			t.Fatalf("Route '%s': max body mismatch: got '%d' - want '%d'", routes[i].Path, routes[i].MaxBody, api.MaxBody)
		}
		if routes[i].Timeout != api.Timeout {
			t.Fatalf("Route '%s': timeout mismatch: got '%v' - want '%v'", routes[i].Path, routes[i].Timeout, api.Timeout)
		}
	}
}

func testCreateKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: failed to create key '%s': %v", i, test.Name, err)
		}
	}
}

func testDeleteKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}

		if test.ShouldFail {
			continue
		}
		if err := client.DeleteKey(ctx, test.Name); err != nil {
			t.Errorf("Test %d: failed to delete key '%s': %v", i, test.Name, err)
		}
	}
}

func testImportKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.ImportKey(ctx, test.Name, &kes.ImportKeyRequest{
			Key:    make([]byte, 32),
			Cipher: kes.AES256,
		})
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}
	}
}

func testDescribeKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}

		if test.ShouldFail {
			continue
		}

		info, err := client.DescribeKey(ctx, test.Name)
		if err != nil {
			t.Errorf("Test %d: failed to describe key '%s': %v", i, test.Name, err)
		}
		if info.Algorithm > kes.ChaCha20 {
			t.Errorf("Test %d: failed to describe key '%s': invalid algorithm '%d'", i, test.Name, info.Algorithm)
		}
		if info.CreatedAt.IsZero() {
			t.Errorf("Test %d: failed to describe key '%s': created_at is zero", i, test.Name)
		}
		if info.CreatedBy.IsUnknown() {
			t.Errorf("Test %d: failed to describe key '%s': created_by is empty", i, test.Name)
		}
	}
}

func testGenerateKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	associatedData := make([]byte, 80)

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}

		if test.ShouldFail {
			continue
		}

		dek, err := client.GenerateKey(ctx, test.Name, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to generate DEK with key '%s': %v", i, test.Name, err)
		}
		plaintext, err := client.Decrypt(ctx, test.Name, dek.Ciphertext, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to decrypt DEK with key '%s': %v", i, test.Name, err)
		}
		if !bytes.Equal(plaintext, dek.Plaintext) {
			t.Errorf("Test %d: plaintext mismatch: got %v - want %v", i, plaintext, dek.Plaintext)
		}

		dek2, err := client.GenerateKey(ctx, test.Name, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to generate DEK with key '%s': %v", i, test.Name, err)
		}
		if bytes.Equal(dek.Plaintext, dek2.Plaintext) {
			t.Errorf("Test %d: generate key is deterministic and produces the same DEKs", i)
		}
		if bytes.Equal(dek.Ciphertext, dek2.Ciphertext) {
			t.Errorf("Test %d: generate key is deterministic and produces the same DEK ciphertexts", i)
		}
	}
}

func testHMAC(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	message1 := []byte("Hello World")
	message2 := []byte("Hello World!")

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}

		if test.ShouldFail {
			continue
		}

		sum1, err := client.HMAC(ctx, test.Name, message1)
		if err != nil {
			t.Errorf("Test %d: failed to compute HMAC with key '%s': %v", i, test.Name, err)
		}
		sum2, err := client.HMAC(ctx, test.Name, message2)
		if err != nil {
			t.Errorf("Test %d: failed to compute HMAC with key '%s': %v", i, test.Name, err)
		}
		if hmac.Equal(sum1, sum2) {
			t.Errorf("Test %d: HMACs of different messages are equal: got '%x' and '%x'", i, sum1, sum2)
		}

		verifySum, err := client.HMAC(ctx, test.Name, message1)
		if err != nil {
			t.Errorf("Test %d: failed to compute HMAC with key '%s': %v", i, test.Name, err)
		}

		if !hmac.Equal(sum1, verifySum) {
			t.Errorf("Test %d: HMACs of equal messages are not equal: got '%x' and '%x'", i, sum1, verifySum)
		}
	}
}

func testEncryptDecryptKey(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	plaintext := make([]byte, mem.KB)
	associatedData := make([]byte, 80)

	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}

		if test.ShouldFail {
			continue
		}

		ciphertext, err := client.Encrypt(ctx, test.Name, plaintext, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to encrypt with key '%s': %v", i, test.Name, err)
		}
		ptext, err := client.Decrypt(ctx, test.Name, ciphertext, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to decrypt with key '%s': %v", i, test.Name, err)
		}
		if !bytes.Equal(ptext, plaintext) {
			t.Errorf("Test %d: plaintext mismatch: got %v - want %v", i, ptext, plaintext)
		}

		ctext, err := client.Encrypt(ctx, test.Name, plaintext, associatedData)
		if err != nil {
			t.Errorf("Test %d: failed to encrypt with key '%s': %v", i, test.Name, err)
		}
		if bytes.Equal(ctext, ciphertext) {
			t.Errorf("Test %d: encryption is deterministic and produces the same ciphertexts", i)
		}
	}
}

func testListKeys(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	var names []string
	client := defaultClient(url)
	for i, test := range validNameTests {
		err := client.CreateKey(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: setup: creating key '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: setup: failed to create key '%s': %v", i, test.Name, err)
		}
		if !test.ShouldFail {
			names = append(names, test.Name)
		}
	}
	slices.Sort(names)

	keys, _, err := client.ListKeys(ctx, "", -1)
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}
	if !slices.Equal(names, keys) {
		t.Fatalf("Failed to list keys: got %v - want %v", keys, names)
	}
}

func testDescribeIdentity(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	var identities []kes.Identity
	for _, test := range validNameTests {
		if validName(test.Name) {
			identities = append(identities, kes.Identity(test.Name))
		}
	}
	if err := srv.UpdatePolicies(map[string]Policy{"policy": {Identities: identities}}); err != nil {
		t.Fatalf("Failed to update server policies: %v", err)
	}

	client := defaultClient(url)
	for i, id := range identities {
		info, err := client.DescribeIdentity(ctx, id)
		if err != nil {
			t.Fatalf("Test %d: failed to describe identity '%s': %v", i, id, err)
		}
		if info.IsAdmin {
			t.Errorf("Test %d: identity '%s' is admin", i, id)
		}
		if !info.ExpiresAt.IsZero() || info.TTL > 0 {
			t.Errorf("Test %d: identity '%s' expires", i, id)
		}
		if info.CreatedBy != defaultIdentity {
			t.Errorf("Test %d: identity '%s' was not created by '%s'", i, id, defaultIdentity)
		}

	}
}

func testListIdentities(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	names := []kes.Identity{
		"8ed87d812abbf280ffa760080873d0d503fdfa9c41c1bf32b4cffd1dc71b1d1c",
		"34d90ce76fbc40ab8354ea8c42c17b3f20e1f63a10f6cef787a94394b02141c4",
		"cd0dd4c3efab6a5744d1e9b1754dbe7f612bd759062d6f17a8ef25f47fc86c54",
		"59ba6afc8e844ba36edcf8ed50c23cb62626ea420e9b9ca7509ab6fa6d13ad3a",
		"disabled",
	}
	if err := srv.UpdatePolicies(map[string]Policy{"policy": {Identities: names}}); err != nil {
		t.Fatalf("Failed to update server policies: %v", err)
	}
	names = append(names, defaultIdentity) // Listing identities always includes the admin identity
	slices.Sort(names)

	client := defaultClient(url)
	identities, _, err := client.ListIdentities(ctx, "", -1)
	if err != nil {
		t.Fatalf("Failed to list identities: %v", err)
	}
	if !slices.Equal(names, identities) {
		t.Fatalf("Failed to list identities: got %v - want %v", identities, names)
	}
}

func testSelfDescribeIdentity(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	client := defaultClient(url)
	info, _, err := client.DescribeSelf(ctx)
	if err != nil {
		t.Fatalf("Failed to self-describe identity: %v", err)
	}
	if !info.IsAdmin {
		t.Error("Failed to self-describe identity: not the admin")
	}
	if info.Identity.String() != defaultIdentity {
		t.Errorf("Failed to self-describe identity: got '%s' - want '%s'", info.Identity.String(), defaultIdentity)
	}
}

func testDescribePolicy(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	policies := make(map[string]Policy)
	for _, test := range validNameTests {
		if validName(test.Name) {
			policies[test.Name] = Policy{}
		}
	}
	if err := srv.UpdatePolicies(policies); err != nil {
		t.Fatalf("Failed to update server policies: %v", err)
	}

	client := defaultClient(url)
	for i, test := range validNameTests {
		info, err := client.DescribePolicy(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: describing policy '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: failed to describe policy '%s': %v", i, test.Name, err)
		}
		if !validName(test.Name) && errors.Is(err, kes.ErrPolicyNotFound) {
			t.Errorf("Test %d: received %v for invalid policy name '%s'", i, err, test.Name)
		}

		if test.ShouldFail {
			continue
		}

		if info.Name != test.Name {
			t.Errorf("Test %d: invalid name: got '%s' - want '%s'", i, info.Name, test.Name)
		}
	}
}

func testReadPolicy(t *testing.T) {
	t.Parallel()

	policy := kes.Policy{
		Allow: map[string]kes.Rule{
			"/v1/status":         {},
			"/v1/ready":          {},
			"/v1/key/create/*":   {},
			"/v1/key/generate/*": {},
			"/v1/key/decrypt/*":  {},
		},
		Deny: map[string]kes.Rule{"/v1/key/decrypt/internal*": {}},
	}

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	policies := make(map[string]Policy)
	for _, test := range validNameTests {
		if validName(test.Name) {
			policies[test.Name] = Policy{
				Allow: policy.Allow,
				Deny:  policy.Deny,
			}
		}
	}
	if err := srv.UpdatePolicies(policies); err != nil {
		t.Fatalf("Failed to update server policies: %v", err)
	}

	client := defaultClient(url)
	for i, test := range validNameTests {
		p, err := client.GetPolicy(ctx, test.Name)
		if err == nil && test.ShouldFail {
			t.Errorf("Test %d: reading policy '%s' should have failed", i, test.Name)
		}
		if err != nil && !test.ShouldFail {
			t.Errorf("Test %d: failed to read policy '%s': %v", i, test.Name, err)
		}
		if !validName(test.Name) && errors.Is(err, kes.ErrPolicyNotFound) {
			t.Errorf("Test %d: received %v for invalid policy name '%s'", i, err, test.Name)
		}

		if test.ShouldFail {
			continue
		}

		if !p.IsSubset(&policy) || !policy.IsSubset(p) {
			t.Errorf("Test %d: policy mismatch: got '%v' - want '%v'", i, p, policy)
		}
	}
}

func testListPolicies(t *testing.T) {
	t.Parallel()

	ctx := testContext(t)
	srv, url := startServer(ctx, nil)
	defer srv.Close()

	var names []string
	policies := make(map[string]Policy)
	for _, test := range validNameTests {
		if validName(test.Name) {
			policies[test.Name] = Policy{}
			names = append(names, test.Name)
		}
	}
	if err := srv.UpdatePolicies(policies); err != nil {
		t.Fatalf("Failed to update server policies: %v", err)
	}
	slices.Sort(names)

	client := defaultClient(url)
	list, _, err := client.ListPolicies(ctx, "", -1)
	if err != nil {
		t.Fatalf("Failed to list policies: %v", err)
	}
	if !slices.Equal(names, list) {
		t.Fatalf("Failed to list policies: got %v - want %v", list, names)
	}
}

var importKeyTests = []struct {
	Key        []byte
	Cipher     kes.KeyAlgorithm
	ShouldFail bool
}{
	{Key: make([]byte, 32), Cipher: kes.AES256},   // 0
	{Key: make([]byte, 32), Cipher: kes.ChaCha20}, // 1

	{Key: make([]byte, 16), Cipher: kes.AES256, ShouldFail: true},       // 2
	{Key: make([]byte, 24), Cipher: kes.ChaCha20, ShouldFail: true},     // 3
	{Key: make([]byte, 32), Cipher: kes.ChaCha20 + 1, ShouldFail: true}, // 4
}
