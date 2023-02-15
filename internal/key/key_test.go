// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/minio/kes-go"
)

var parseTests = []struct {
	Raw string

	Bytes     []byte
	Algorithm kes.KeyAlgorithm
	CreatedAt time.Time
	CreatedBy kes.Identity

	ShouldFail bool
}{
	{Raw: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, Bytes: make([]byte, 32)},
	{Raw: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`, Bytes: append(make([]byte, 31), 1)},
	{Raw: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`, Bytes: mustDecodeHex("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41")},

	{
		Raw:       `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E=","algorithm":"AES256-GCM_SHA256","created_at":"2009-11-10T23:00:00Z","created_by":"40235905b7b83e0537a002db523cd019d6709b899adc249c957860cd00fa9f78"}`,
		Bytes:     mustDecodeHex("27caa63b2115d9c7b6ca8002fb9b7463b0923ff853329a4bed71e9027c9cfb41"),
		Algorithm: kes.AES256_GCM_SHA256,
		CreatedAt: mustDecodeTime("2009-11-10T23:00:00Z"),
		CreatedBy: "40235905b7b83e0537a002db523cd019d6709b899adc249c957860cd00fa9f78",
	},
	{
		Raw:       `{"bytes":"9ew6BCae3+13sniOUwttEJ62amg98YXc0OW0WBhNiCY=","algorithm":"XCHACHA20-POLY1305","created_at":"2009-11-10T23:00:00Z","created_by":"189d9de5331e3ee8abe9e4bd40d474ad621d79ccf83a711f6ac68050eb15a52a"}`,
		Bytes:     mustDecodeHex("f5ec3a04269edfed77b2788e530b6d109eb66a683df185dcd0e5b458184d8826"),
		Algorithm: kes.XCHACHA20_POLY1305,
		CreatedAt: mustDecodeTime("2009-11-10T23:00:00Z"),
		CreatedBy: "189d9de5331e3ee8abe9e4bd40d474ad621d79ccf83a711f6ac68050eb15a52a",
	},

	{Raw: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: {
	{Raw: `{bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing first: "
	{Raw: `{"bytes""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: :
	{Raw: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, ShouldFail: true},  // Missing final }
}

func TestParse(t *testing.T) {
	for i, test := range parseTests {
		key, err := Parse([]byte(test.Raw))
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to parse key: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Parsing should have failed but succeeded", i)
		}
		if err == nil {
			if !bytes.Equal(key.bytes, test.Bytes) {
				t.Fatalf("Test %d: got %x - want %x", i, key.bytes, test.Bytes)
			}
			if key.Algorithm() != test.Algorithm {
				t.Fatalf("Test %d: algorithm mismatch: got %v - want %v", i, key.Algorithm(), test.Algorithm)
			}
			if key.CreatedAt() != test.CreatedAt {
				t.Fatalf("Test %d: created at mismatch: got %v - want %v", i, key.CreatedAt(), test.CreatedAt)
			}
			if key.CreatedBy() != test.CreatedBy {
				t.Fatalf("Test %d: created by mismatch: got %v - want %v", i, key.CreatedBy(), test.CreatedBy)
			}
		}
	}
}

var keyWrapTests = []struct {
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

func TestKeyWrap(t *testing.T) {
	algorithms := []kes.KeyAlgorithm{kes.AES256_GCM_SHA256, kes.XCHACHA20_POLY1305}
	for _, a := range algorithms {
		key, err := Random(a, "")
		if err != nil {
			t.Fatalf("Failed to create key: %v", err)
		}
		for i, test := range keyWrapTests {
			data := make([]byte, test.KeyLen)
			ciphertext, err := key.Wrap(data, test.AssociatedData)
			if err != nil {
				t.Logf("Test %d: Algorithm: %v , Secret: %x\n", i, key.Algorithm(), key.bytes)
				t.Fatalf("Test %d: Failed to wrap data: %v", i, err)
			}
			plaintext, err := key.Unwrap(ciphertext, test.AssociatedData)
			if err != nil {
				t.Logf("Test %d: Algorithm: %v , Secret: %x\n", i, key.Algorithm(), key.bytes)
				t.Fatalf("Test %d: Failed to unwrap data: %v", i, err)
			}
			if !bytes.Equal(data, plaintext) {
				t.Logf("Test %d: Secret: %x\n", i, key.bytes)
				t.Fatalf("Test %d: Original plaintext does not match unwrapped plaintext", i)
			}
		}
	}
}

var keyUnwrapTests = []struct {
	Algorithm      kes.KeyAlgorithm
	Ciphertext     string
	AssociatedData []byte

	ShouldFail bool
	Err        error
}{
	{ // 0
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
	},
	{ // 1
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
	},
	{ // 2
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","id":"66687aadf862bd776c8fc18b8e9f8e20","iv":"EC0eZp7Pqt+LnkOae5xaAg==","nonce":"X1ejXKmH/ugFZPkk","bytes":"wIGBTDs6aOvsqJfekZ0PYRT/OHyFX2TXqeNwl1SLXOI="}`,
		AssociatedData: nil,
	},
	{ // 3
		Algorithm:      kes.AES256_GCM_SHA256,
		Ciphertext:     string(mustDecodeB64("lbFBRVMyNTYtR0NNX1NIQTI1NtkgNjY2ODdhYWRmODYyYmQ3NzZjOGZjMThiOGU5ZjhlMjDEEExv7LAd4oz0SaHZrX5LBufEDEKME1ow1CDfUFrqv8QgJuy7Sw+jVqz99TK1HV851LT3K4mwwDv46TB2ngWkAJQ=")),
		AssociatedData: nil,
	},
	{ // 4
		Algorithm:      kes.XCHACHA20_POLY1305,
		Ciphertext:     string(mustDecodeB64("lbJYQ0hBQ0hBMjAtUE9MWTEzMDXZIDY2Njg3YWFkZjg2MmJkNzc2YzhmYzE4YjhlOWY4ZTIwxBBAr+aptD4x2+qfOhiErbnkxAxYs8RmNC1JJXD1hiHEIJ2KqM0jjkME7ndx8nyVseesN83Np0rM5ejVUun+fNFu")),
		AssociatedData: nil,
	},

	{ // 5
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // Invalid algorithm
		Err:            kes.ErrDecrypt,
	},
	{ // 6
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"EjOY4JKqjIrPmQ5z1KSR8zlhggY=","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid IV length
		Err:            kes.ErrDecrypt,
	},
	{ // 7
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"SXAbms731/c=","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
		Err:            kes.ErrDecrypt,
	},
	{ // 8
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"efY+4kYF9n8=","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
		Err:            kes.ErrDecrypt,
	},
	{ // 9
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"QTza1g5oX3f9cGJMbY1xJwWPj1F7R2VnNl6XpFKYQy0="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
		Err:            kes.ErrDecrypt,
	},
	{ // 10
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
		Err:            kes.ErrDecrypt,
	},
	{ // 11
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256" "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid JSON
		Err:            kes.ErrDecrypt,
	},
	{ // 12
		Algorithm:      kes.KeyAlgorithmUndefined,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256", "id":"00010203040506070809101112131415", "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid key ID
		Err:            kes.ErrDecrypt,
	},
}

func TestKeyUnwrap(t *testing.T) {
	Plaintext := make([]byte, 16)
	for i, test := range keyUnwrapTests {
		key, err := New(test.Algorithm, make([]byte, Len(test.Algorithm)), "")
		if err != nil {
			t.Fatalf("Test %d: Failed to create key: %v", i, err)
		}
		plaintext, err := key.Unwrap([]byte(test.Ciphertext), test.AssociatedData)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: Failed to unwrap ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: Expected to fail but succeeded", i)
		}
		if test.ShouldFail && err != test.Err {
			t.Fatalf("Test %d: Invalid error response: got %v - want %v", i, err, test.Err)
		}
		if !test.ShouldFail && !bytes.Equal(plaintext, Plaintext) {
			t.Fatalf("Test %d: Plaintext mismatch: got %x - want %x", i, plaintext, Plaintext)
		}
	}
}

func mustDecodeTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
