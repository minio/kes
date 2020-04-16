// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/secure-io/sio-go/sioutil"
)

var secretStringTests = []struct {
	Secret Secret
	String string
}{
	{Secret: Secret{}, String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`},
	{Secret: mustDecodeSecret("0000000000000000000000000000000000000000000000000000000000000001"), String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`},
	{Secret: mustDecodeSecret("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41"), String: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`},
}

func TestSecretString(t *testing.T) {
	for i, test := range secretStringTests {
		if s := test.Secret.String(); s != test.String {
			t.Fatalf("Test %d: got %s - want %s", i, s, test.String)
		}
	}
}

var secretParseStringTests = []struct {
	Secret     Secret
	String     string
	ShouldFail bool
}{
	{Secret: Secret{}, String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`},
	{Secret: mustDecodeSecret("0000000000000000000000000000000000000000000000000000000000000001"), String: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`},
	{Secret: mustDecodeSecret("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41"), String: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`},
	{Secret: Secret{}, String: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: {
	{Secret: Secret{}, String: `{bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing first: "
	{Secret: Secret{}, String: `{"bytes""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: :
	{Secret: Secret{}, String: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, ShouldFail: true},  // Missing final }
}

func TestParseString(t *testing.T) {
	for i, test := range secretParseStringTests {
		secret, err := ParseSecret(test.String)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to parse string: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Parsing should have failed but it succeeded", i)
		}
		if err == nil && secret != test.Secret {
			t.Fatalf("Test %d: got %x - want %x", i, secret, test.Secret)
		}
	}
}

var secretWrapTests = []struct {
	KeyLen         int
	AssociatedData []byte
}{
	{KeyLen: 0, AssociatedData: nil},                                                // 0
	{KeyLen: 1, AssociatedData: nil},                                                // 1
	{KeyLen: 16, AssociatedData: make([]byte, 0)},                                   // 2
	{KeyLen: 32, AssociatedData: mustDecodeHex("ff")},                               // 3
	{KeyLen: 128, AssociatedData: make([]byte, 1024)},                               // 4
	{KeyLen: 1024, AssociatedData: mustDecodeHex("a2e31cb681f3")},                   // 5
	{KeyLen: 63, AssociatedData: mustDecodeHex("cb653b4c5426e0d41f5ae673ffa0f659")}, // 6
}

func TestSecretWrap(t *testing.T) {
	var secret Secret
	copy(secret[:], sioutil.MustRandom(len(secret)))

	for i, test := range secretWrapTests {
		data := make([]byte, test.KeyLen)
		ciphertext, err := secret.Wrap(data, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Failed to wrap data: %v", i, err)
		}
		plaintext, err := secret.Unwrap(ciphertext, test.AssociatedData)
		if err != nil {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Failed to unwrap data: %v", i, err)
		}
		if !bytes.Equal(data, plaintext) {
			t.Logf("Test %d: Secret: %x\n", i, secret)
			t.Fatalf("Test %d: Original plaintext does not match unwrapped plaintext", i)
		}
	}
}

var secretUnwrapTests = []struct {
	Ciphertext     string
	AssociatedData []byte
	ShouldFail     bool
}{
	{ // 0
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
	},
	{ // 1
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
	},
	{ // 2
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // Invalid algorithm
	},
	{ // 3
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"EjOY4JKqjIrPmQ5z1KSR8zlhggY=","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid IV length
	},
	{ // 4
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"SXAbms731/c=","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 5
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"efY+4kYF9n8=","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 6
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"QTza1g5oX3f9cGJMbY1xJwWPj1F7R2VnNl6XpFKYQy0="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 7
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 8
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256" "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid JSON
	},
}

func TestSecrectUnwrap(t *testing.T) {
	var secret Secret
	Plaintext := make([]byte, 16)
	for i, test := range secretUnwrapTests {
		plaintext, err := secret.Unwrap([]byte(test.Ciphertext), test.AssociatedData)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to unwrap ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Expected to fail but succeeded", i)
		}
		if !test.ShouldFail && !bytes.Equal(plaintext, Plaintext) {
			t.Fatalf("Test %d: Plaintext mismatch: got %x - want %x", i, plaintext, Plaintext)
		}
	}
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustDecodeSecret(s string) Secret {
	b := mustDecodeHex(s)

	var secret Secret
	if len(b) != len(secret) {
		panic(fmt.Sprintf("invalid secret length - got: %d want: %d", len(b), len(secret)))
	}
	copy(secret[:], b)
	return secret
}
