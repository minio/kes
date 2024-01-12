// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestEncodeKeyVersion(t *testing.T) {
	t.Parallel()

	for i, test := range encodeSecretKeyVersionTests {
		b, err := EncodeKeyVersion(test.Key)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to encode key: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: encoded invalid key successfully", i)
		}
		if test.ShouldFail {
			continue
		}

		key, err := ParseKeyVersion(b)
		if err != nil {
			t.Fatalf("Test %d: failed to decode encoded key: %v", i, err)
		}
		if key != test.Key {
			t.Fatalf("Test %d: got '%+v' - want '%+v'", i, key, test.Key)
		}
	}
}

func TestSecretKeyEncrypt(t *testing.T) {
	t.Parallel()

	for i, test := range secretKeyEncryptTests {
		plaintext := mustDecodeB64(test.Plaintext)
		associatedData := mustDecodeB64(test.AssociatedData)

		ciphertext, err := test.Key.Encrypt(plaintext, associatedData)
		if err != nil {
			t.Fatalf("Test %d: failed to encrypt plaintext: %v", i, err)
		}

		p, err := test.Key.Decrypt(ciphertext, associatedData)
		if err != nil {
			t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
		}
		if p := base64.StdEncoding.EncodeToString(p); p != test.Plaintext {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, p, test.Plaintext)
		}
	}
}

func TestSecretKeyDecrypt(t *testing.T) {
	t.Parallel()

	for i, test := range secretKeyDecryptTests {
		plaintext, err := test.Key.Decrypt([]byte(test.Ciphertext), mustDecodeB64(test.AssociatedData))
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: decrypted invalid ciphertext successfully", i)
		}
		if test.ShouldFail {
			continue
		}
		if p := base64.StdEncoding.EncodeToString(plaintext); p != test.Plaintext {
			t.Fatalf("Test %d: got %s - want %s", i, p, test.Plaintext)
		}
	}
}

func TestParseKeyVersion(t *testing.T) {
	for i, test := range parseKeyVersionTests {
		key, err := ParseKeyVersion([]byte(test.Raw))
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to parse key: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: parsing should have failed but succeeded", i)
		}
		if test.ShouldFail {
			continue
		}

		if key.Key != test.Key.Key {
			t.Fatalf("Test %d: got '%+v' - want '%+v'", i, key.Key, test.Key.Key)
		}
		if key.HMACKey != test.Key.HMACKey {
			t.Fatalf("Test %d: got '%+v' - want '%+v'", i, key.HMACKey, test.Key.HMACKey)
		}
		if key.CreatedAt != test.Key.CreatedAt {
			t.Fatalf("Test %d: got %v - want %v", i, key.CreatedAt, test.Key.CreatedAt)
		}
		if key.CreatedBy != test.Key.CreatedBy {
			t.Fatalf("Test %d: got %v - want %v", i, key.CreatedBy, test.Key.CreatedBy)
		}
	}
}

var encodeSecretKeyVersionTests = []struct {
	Key        KeyVersion
	ShouldFail bool
}{
	{ // 0
		Key: KeyVersion{
			Key:       mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			HMACKey:   mustHMACKey(SHA256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			CreatedAt: mustTime("2024-01-12T11:39:20.886816+01:00"),
			CreatedBy: "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22",
		},
	},
	{ // 1
		Key: KeyVersion{
			Key:       mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			CreatedAt: mustTime("2024-01-12T11:39:20.886816+01:00"),
			CreatedBy: "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22",
		},
		ShouldFail: true,
	},
	{ // 2
		Key: KeyVersion{
			HMACKey:   mustHMACKey(SHA256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
			CreatedAt: mustTime("2024-01-12T11:39:20.886816+01:00"),
			CreatedBy: "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22",
		},
		ShouldFail: true,
	},
}

var secretKeyEncryptTests = []struct {
	Key            SecretKey
	Plaintext      string
	AssociatedData string
}{
	{ // 0
		Key:       mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext: "AAAAAAAAAAAAAAAAAAAAAA==",
	},
	{ // 1
		Key:       mustSecretKey(AES256, "dDHbTWgo+Yh3u804SYB5OyVMy6RiLeJYBQth1f6KlEU="),
		Plaintext: "AAAAAAAAAAAAAAAAAAAAAA==",
	},
	{ // 2
		Key:            mustSecretKey(AES256, "dDHbTWgo+Yh3u804SYB5OyVMy6RiLeJYBQth1f6KlEU="),
		Plaintext:      "CLcJoykFCWZDkEIiUq9bJRqwCwW9ZDvdgu8EMA==",
		AssociatedData: "AAAAAAAAAAAAAAAAAAAAAA==",
	},
	{ // 3
		Key:            mustSecretKey(ChaCha20, "dDHbTWgo+Yh3u804SYB5OyVMy6RiLeJYBQth1f6KlEU="),
		Plaintext:      "CLcJoykFCWZDkEIiUq9bJRqwCwW9ZDvdgu8EMA==",
		AssociatedData: "AAAAAAAAAAAAAAAAAAAAAA==",
	},
}

var secretKeyDecryptTests = []struct {
	Key            SecretKey
	Plaintext      string
	Ciphertext     string
	AssociatedData string
	ShouldFail     bool
}{
	{ // 0
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`, // JSON
	},
	{ // 1
		Key:        mustSecretKey(ChaCha20, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`, // JSON
	},
	{ // 2
		Key:        mustSecretKey(ChaCha20, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: `{"aead":"ChaCha20Poly1305","id":"66687aadf862bd776c8fc18b8e9f8e20","iv":"EC0eZp7Pqt+LnkOae5xaAg==","nonce":"X1ejXKmH/ugFZPkk","bytes":"wIGBTDs6aOvsqJfekZ0PYRT/OHyFX2TXqeNwl1SLXOI="}`, // JSON
	},
	{ // 3
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: string(mustDecodeB64("lbFBRVMyNTYtR0NNX1NIQTI1NtkgNjY2ODdhYWRmODYyYmQ3NzZjOGZjMThiOGU5ZjhlMjDEEExv7LAd4oz0SaHZrX5LBufEDEKME1ow1CDfUFrqv8QgJuy7Sw+jVqz99TK1HV851LT3K4mwwDv46TB2ngWkAJQ=")), // MSGP
	},
	{ // 4
		Key:        mustSecretKey(ChaCha20, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: string(mustDecodeB64("lbJYQ0hBQ0hBMjAtUE9MWTEzMDXZIDY2Njg3YWFkZjg2MmJkNzc2YzhmYzE4YjhlOWY4ZTIwxBBAr+aptD4x2+qfOhiErbnkxAxYs8RmNC1JJXD1hiHEIJ2KqM0jjkME7ndx8nyVseesN83Np0rM5ejVUun+fNFu")), // MSGP
	},
	{ // 5
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Plaintext:  "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext: string(mustDecodeB64("zwdDgHeRlIFRnJ7+DIhs/ka7GFK2CFSfDELqg1VCyTQzZ58o7MAdupMLk3ZjlMo2ZUDwldL2o41nAWDc")),
	},
	{ // 6
		Key:            mustSecretKey(AES256, "dDHbTWgo+Yh3u804SYB5OyVMy6RiLeJYBQth1f6KlEU="),
		Plaintext:      "CLcJoykFCWZDkEIiUq9bJRqwCwW9ZDvdgu8EMA==",
		AssociatedData: "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext:     string(mustDecodeB64("s2gmfQHeGdlyL8x1yEWSACUV3GrSoz3t160hugMgzKWgyqesXDVUJ5Dw5Mt076rR1PNiU9X4YjLH14D8a81t2r2xsz4gVZac")),
	},
	{ // 7
		Key:            mustSecretKey(ChaCha20, "dDHbTWgo+Yh3u804SYB5OyVMy6RiLeJYBQth1f6KlEU="),
		Plaintext:      "CLcJoykFCWZDkEIiUq9bJRqwCwW9ZDvdgu8EMA==",
		AssociatedData: "AAAAAAAAAAAAAAAAAAAAAA==",
		Ciphertext:     string(mustDecodeB64("gO4woRIswAJdjUjW7z2ApsSQxJlwB24yjLrmH4eI7sB0uh5nfEJfk9ybTPFft5FRFaZCVBmzhx7OJs9n0WWtxH3sySIxecIK")),
	},

	{ // 8
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"AES-256-GCM","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		ShouldFail: true, // Invalid algorithm
	},
	{ // 9
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"EjOY4JKqjIrPmQ5z1KSR8zlhggY=","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		ShouldFail: true, // invalid IV length
	},
	{ // 10
		Key:        mustSecretKey(ChaCha20, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"SXAbms731/c=","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		ShouldFail: true, // invalid nonce length
	},
	{ // 11
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"efY+4kYF9n8=","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		ShouldFail: true, // invalid nonce length
	},
	{ // 12
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"QTza1g5oX3f9cGJMbY1xJwWPj1F7R2VnNl6XpFKYQy0="}`,
		ShouldFail: true, // ciphertext not authentic
	},
	{ // 13
		Key:        mustSecretKey(ChaCha20, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		ShouldFail: true, // ciphertext not authentic
	},
	{ // 14
		Key:        mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		Ciphertext: `{"aead":"AES-256-GCM-HMAC-SHA-256" "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		ShouldFail: true, // invalid JSON
	},
}

var parseKeyVersionTests = []struct {
	Raw        string
	Key        KeyVersion
	ShouldFail bool
}{
	{
		Raw: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		Key: KeyVersion{
			Key: mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		},
	},
	{
		Raw: `{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}`,
		Key: KeyVersion{
			Key: mustSecretKey(AES256, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="),
		},
	},
	{
		Raw: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="}`,
		Key: KeyVersion{
			Key: mustSecretKey(AES256, "J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="),
		},
	},
	{
		Raw: `{"bytes":"J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E=","algorithm":"AES256-GCM_SHA256","created_at":"2009-11-10T23:00:00Z","created_by":"40235905b7b83e0537a002db523cd019d6709b899adc249c957860cd00fa9f78"}`,
		Key: KeyVersion{
			Key:       mustSecretKey(AES256, "J8qmOyEV2ce2yoAC+5t0Y7CSP/hTMppL7XHpAnyc+0E="),
			CreatedAt: mustTime("2009-11-10T23:00:00Z"),
			CreatedBy: "40235905b7b83e0537a002db523cd019d6709b899adc249c957860cd00fa9f78",
		},
	},
	{
		Raw: `{"bytes":"9ew6BCae3+13sniOUwttEJ62amg98YXc0OW0WBhNiCY=","algorithm":"XCHACHA20-POLY1305","created_at":"2009-11-10T23:00:00Z","created_by":"189d9de5331e3ee8abe9e4bd40d474ad621d79ccf83a711f6ac68050eb15a52a"}`,
		Key: KeyVersion{
			Key:       mustSecretKey(ChaCha20, "9ew6BCae3+13sniOUwttEJ62amg98YXc0OW0WBhNiCY="),
			CreatedAt: mustTime("2009-11-10T23:00:00Z"),
			CreatedBy: "189d9de5331e3ee8abe9e4bd40d474ad621d79ccf83a711f6ac68050eb15a52a",
		},
	},
	{
		Raw: "CiQKIMiHG7XrN94FuwblJJor4f7f6rbqAl7DwsLaiIoyz0D2EAESJAognLXl4yqa4cjZTcSbsU6sNnN8kP9ARWkXwa20YQZa9HgQARoMCNithK0GEID67qYDIkAzZWNmY2RmMzhmY2JlMTQxYWUyNmExMDMwZjgxZTk2Yjc1MzM2NWE0Njc2MGFlNmI1Nzg2OThhOTdjNTlmZDIy",
		Key: KeyVersion{
			Key:       mustSecretKey(AES256, "yIcbtes33gW7BuUkmivh/t/qtuoCXsPCwtqIijLPQPY="),
			HMACKey:   mustHMACKey(SHA256, "nLXl4yqa4cjZTcSbsU6sNnN8kP9ARWkXwa20YQZa9Hg="),
			CreatedAt: mustTime("2024-01-12T11:39:20.886816+01:00"),
			CreatedBy: "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22",
		},
	},
	{Raw: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: {
	{Raw: `{bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing first: "
	{Raw: `{"bytes""AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`, ShouldFail: true}, // Missing: :
	{Raw: `"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`, ShouldFail: true},  // Missing final }
}

func mustSecretKey(cipher SecretKeyType, base64Key string) SecretKey {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		panic(err)
	}
	sk, err := NewSecretKey(cipher, key)
	if err != nil {
		panic(err)
	}
	return sk
}

func mustHMACKey(hash Hash, base64Key string) HMACKey {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		panic(err)
	}
	sk, err := NewHMACKey(hash, key)
	if err != nil {
		panic(err)
	}
	return sk
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			panic(err)
		}
	}
	t = t.UTC()
	return t
}
