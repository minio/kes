// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"testing"

	"github.com/minio/kes"
	"github.com/secure-io/sio-go/sioutil"
)

// The integration tests require a KES server instance to run against.
// By default, this instance is a KES server running at https://play.min.io:7373.
//
// The client running the test has to have extensive privileges since it calls
// most/all server APIs. Typically the root identity is used for this purpose.
// By default, the client is the root identity of the https://play.min.io:7373 instance.
//
// When running the integration test the endpoint, client key and client certificate
// can be customized with the corresponding flags listed below.
//
// To run the integration tests (in addition to unit tests) the '-integration' flag has
// to be set. By default, only unit tests and no integration tests are executed.
//
// If the KES server uses an e.g. self-signed TLS certificate, i.e. when running a local
// KES server, the client-side TLS certificate verification can be disabled with the '-k' flag.
//
// Examples:
//   Run the integration tests against https://play.min.io using the default root identity:
//   go test -v -integration
//
//   Only run the 'CreateKey' integration test against https://play.min.io using the default root identity:
//   go test -v -integration -run=CreateKey
//
//   Run the integration tests against a local KES server (https://127.0.0.1:7373) using
//   a custom root identity.
//   go  test -v -k -integration -endpoint=https://127.0.0.1:7373 -key=<client.key> -cert<client.cert>
var (
	IsIntegrationTest  = flag.Bool("integration", false, "Run integration tests in addition to unit tests")
	Endpoint           = flag.String("endpoint", "https://play.min.io:7373", "The KES server endpoint for integration tests")
	ClientKey          = flag.String("key", "root.key", "Path to the client private key for integration tests")
	ClientCert         = flag.String("cert", "root.cert", "Path to the client certificate for integration tests")
	InsecureSkipVerify = flag.Bool("k", false, "Disable X.509 certificate verification")
)

func TestCreateKey(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	key := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.CreateKey(key); err != nil {
		t.Fatalf("Failed to create key '%s': %v", key, err)
	}
	defer client.DeleteKey(key) // Cleanup

	if err := client.CreateKey(key); err != kes.ErrKeyExists {
		t.Fatalf("Creating the key '%s' twice should have failed: got %v - want %v", key, err, kes.ErrKeyExists)
	}
}

var importKeyTests = []struct {
	Key []byte

	Plaintext  []byte
	Context    []byte
	Ciphertext []byte
}{
	{
		Key:        make([]byte, 32),
		Plaintext:  make([]byte, 32),
		Context:    nil,
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaXYiOiJ1SUlmSG1OanY2MGRBbUlRL0haT3JBPT0iLCJub25jZSI6IlNEdi8wTlpWaG02R1lGS0wiLCJieXRlcyI6InBqU204UDkyRXlzZE5GZW4rQWdJUEQxeWl4KzNmWTZvUkE0SGdXYzdlZ1J5ckZtNzJ0Z1dYUitFTVlrRHZxYmUifQ=="),
	},
	{
		Key:        make([]byte, 32),
		Plaintext:  mustDecodeB64("FO+Mnrs7Lm/+ejCikk2Xxh1ptfPK8eBwk08WqOTIQ38="),
		Context:    nil,
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaXYiOiJURWR5c0RaSlpBUExRd1FXdnhTL2R3PT0iLCJub25jZSI6ImIxbGphZVBiR0RnUUtwVkkiLCJieXRlcyI6IkxRWHBSS0Jra1UzbjJ0bVVzT09hOS9YN1lJRGdTU2VWNXZCcm9NWXhDNGtvMkNWd25MaFB5WXNrZVN6UkM1MWwifQ=="),
	},
	{
		Key:        mustDecodeB64("Ocxv4Vf3eur17x6R0mO6P15KPj+L7h2qpe6ZxRy5eiE="),
		Plaintext:  mustDecodeB64("WKDdYkXJ21/HD9lNNBdbUJ3UuwoND/a7eC5bh+0Tbn2DeFSp5IzDe8bOgqK+7F7ortyViprO7Zwt5GF67/ooXQ=="),
		Context:    mustDecodeB64("Eb2sb9zyRPKXbgu5"),
		Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaXYiOiJGd043WU04ZlVzU1loUFdzZVBmRUt3PT0iLCJub25jZSI6ImFoeG9GYmh1V0IzVHZma1oiLCJieXRlcyI6Im9rY241MUZwNUJsZEoxbGN3ZThLREJXZUhzZEhVQllaaUNkUWxrQXREak9rV1R6TlZvWW05ZEswRXRPZmw3MG1zNVZWSmxqdnZWNTF0VFFhSWFDK2NZTndUSjl5VXNYdHpkUUR2L0lKdHFvPSJ9"),
	},
}

func TestImportKey(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	key := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	for i, test := range importKeyTests {
		if err := client.ImportKey(key, test.Key); err != nil {
			t.Fatalf("Failed to import key '%s': %v", key, err)
		}

		plaintext, err := client.Decrypt(key, test.Ciphertext, test.Context)
		if err != nil {
			client.DeleteKey(key) // Cleanup
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if !bytes.Equal(plaintext, test.Plaintext) {
			client.DeleteKey(key) // Cleanup
			t.Fatalf("Test %d: Plaintext mismatch: got '%s' - want '%s'", i, plaintext, test.Plaintext)
		}
		client.DeleteKey(key) // Cleanup
	}
}

var generateKeyTests = []struct {
	Context    []byte
	ShouldFail bool
}{
	{Context: nil, ShouldFail: false},
	{Context: []byte("Request made by MinIO instance 3afe...49ff"), ShouldFail: false},
	{Context: make([]byte, 512*1024), ShouldFail: false},
	{Context: make([]byte, 1024*1024), ShouldFail: true}, // exceeds request size limit
}

func TestGenerateKey(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	key := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.CreateKey(key); err != nil {
		t.Fatalf("Failed to create key '%s': %v", key, err)
	}
	defer client.DeleteKey(key) // Cleanup

	for i, test := range generateKeyTests {
		dek, err := client.GenerateKey(key, test.Context)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Test should have failed but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to generate DEK: %v", i, err)
		}
		if !test.ShouldFail {
			plaintext, err := client.Decrypt(key, dek.Ciphertext, test.Context)
			if err != nil {
				t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
			}
			if !bytes.Equal(plaintext, dek.Plaintext) {
				t.Fatalf("Test %d: Plaintext mismatch: got '%s' - want '%s'", i, plaintext, dek.Plaintext)
			}
		}
	}
}

var encryptKeyTests = []struct {
	Plaintext  []byte
	Context    []byte
	ShouldFail bool
}{
	{Plaintext: nil, Context: nil, ShouldFail: false},
	{Plaintext: []byte("Hello World"), Context: nil, ShouldFail: false},
	{Plaintext: nil, Context: []byte("Request made by MinIO instance 3afe...49ff"), ShouldFail: false},
	{Plaintext: []byte("Hello World"), Context: []byte("Request made by MinIO instance 3afe...49ff"), ShouldFail: false},
	{Plaintext: make([]byte, 512*1024), Context: make([]byte, 512*1024), ShouldFail: true}, // exceeds request size limit
	{Plaintext: make([]byte, 1024*1024), Context: nil, ShouldFail: true},                   // exceeds request size limit
}

func TestEncryptKey(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	key := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.CreateKey(key); err != nil {
		t.Fatalf("Failed to create key '%s': %v", key, err)
	}
	defer client.DeleteKey(key) // Cleanup

	for i, test := range encryptKeyTests {
		_, err = client.Encrypt(key, test.Plaintext, test.Context)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Test should have failed but succeeded", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to generate DEK: %v", i, err)
		}
	}
}

var decryptKeyTests = []struct {
	Plaintext []byte
	Context   []byte
}{
	{Plaintext: nil, Context: nil},
	{Plaintext: []byte("Hello World"), Context: nil},
	{Plaintext: nil, Context: []byte("Request made by MinIO instance 3afe...49ff")},
	{Plaintext: []byte("Hello World"), Context: []byte("Request made by MinIO instance 3afe...49ff")},
}

func TestDecryptKey(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	key := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.CreateKey(key); err != nil {
		t.Fatalf("Failed to create key '%s': %v", key, err)
	}
	defer client.DeleteKey(key) // Cleanup

	for i, test := range decryptKeyTests {
		ciphertext, err := client.Encrypt(key, test.Plaintext, test.Context)
		if err != nil {
			t.Fatalf("Test %d: Failed to encrypt plaintext: %v", i, err)
		}
		plaintext, err := client.Decrypt(key, ciphertext, test.Context)
		if err != nil {
			t.Fatalf("Test %d: Failed to decrypt ciphertext: %v", i, err)
		}
		if !bytes.Equal(plaintext, test.Plaintext) {
			t.Fatalf("Test %d: Plaintext mismatch: got '%s' - want '%s'", i, plaintext, test.Plaintext)
		}
	}
}

var readWritePolicyTests = []struct {
	Policy *kes.Policy
}{
	{Policy: newPolicy()},
	{Policy: newPolicy("/version")},
	{Policy: newPolicy("/v1/key/create/*", "/v1/key/delete/*")},
	{Policy: newPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-minio-key")},
	{Policy: newPolicy("/v1/policy/delete/my-policy", "/v1/policy/create/my-*")},
	{Policy: newPolicy("/v1/key/*/*", "/v1/identity/*/*")},
}

func TestReadWritePolicy(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	name := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	for i, test := range readWritePolicyTests {
		if err := client.SetPolicy(name, test.Policy); err != nil {
			t.Fatalf("Test %d: Failed to create policy '%s': %v", i, name, err)
		}
		if _, err = client.GetPolicy(name); err != nil {
			client.DeletePolicy(name) // cleanup
			t.Fatalf("Test %d: Failed to read policy '%s': %v", i, name, err)
		}
		client.DeletePolicy(name) // cleanup
	}
}

func TestAssignIdentity(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	name := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.SetPolicy(name, newPolicy("/version")); err != nil {
		t.Fatalf("Failed to create policy '%s': %v", name, err)
	}
	defer client.DeletePolicy(name)

	identity := kes.Identity(hex.EncodeToString(sioutil.MustRandom(32)))
	if err := client.AssignIdentity(name, identity); err != nil {
		t.Fatalf("Failed to assign identity '%s' to policy '%s': %v", identity, name, err)
	}
}

func TestForgetIdentity(t *testing.T) {
	if !*IsIntegrationTest {
		t.SkipNow()
	}

	client, err := newClient()
	if err != nil {
		t.Fatalf("Failed to create KES client: %v", err)
	}

	name := fmt.Sprintf("KES-test-%x", sioutil.MustRandom(12))
	if err := client.SetPolicy(name, newPolicy("/version")); err != nil {
		t.Fatalf("Failed to create policy '%s': %v", name, err)
	}
	defer client.DeletePolicy(name)

	identity := kes.Identity(hex.EncodeToString(sioutil.MustRandom(32)))
	if err := client.AssignIdentity(name, identity); err != nil {
		t.Fatalf("Failed to assign identity '%s' to policy '%s': %v", identity, name, err)
	}
	if err := client.ForgetIdentity(identity); err != nil {
		t.Fatalf("Failed to forget identity '%s': %v", identity, err)
	}
}

func newClient() (*kes.Client, error) {
	certificate, err := tls.LoadX509KeyPair(*ClientCert, *ClientKey)
	if err != nil {
		return nil, err
	}
	return kes.NewClientWithConfig(*Endpoint, &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		InsecureSkipVerify: *InsecureSkipVerify,
	}), nil
}

func newPolicy(patterns ...string) *kes.Policy {
	policy, err := kes.NewPolicy(patterns...)
	if err != nil {
		panic(err)
	}
	return policy
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
