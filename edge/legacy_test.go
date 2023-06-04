// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/crypto"
)

func TestLegacyDecrypt(t *testing.T) {
	Plaintext := make([]byte, 16)
	for i, test := range legacyDecryptTests {
		key, err := crypto.NewSecretKey(test.Cipher, make([]byte, 32))
		if err != nil {
			t.Fatalf("Test %d: failed to create key: %v", i, err)
		}
		ciphertext, err := decodeCiphertext([]byte(test.Ciphertext))
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to decode ciphertext: %v", i, err)
		}

		plaintext, err := key.Decrypt(ciphertext, test.AssociatedData)
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to decrypt ciphertext: %v", i, err)
		}
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should have failed to decrypt ciphertext: '%s'", i, test.Ciphertext)
		}
		if !test.ShouldFail && !bytes.Equal(plaintext, Plaintext) {
			t.Fatalf("Test %d: plaintext mismatch: got %x - want %x", i, plaintext, Plaintext)
		}
	}
}

var legacyDecryptTests = []struct {
	Cipher         crypto.SecretKeyCipher
	Ciphertext     string
	AssociatedData []byte

	ShouldFail bool
}{
	{ // 0
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
	},
	{ // 1
		Cipher:         kes.ChaCha20,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
	},
	{ // 2
		Cipher:         kes.ChaCha20,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","id":"66687aadf862bd776c8fc18b8e9f8e20","iv":"EC0eZp7Pqt+LnkOae5xaAg==","nonce":"X1ejXKmH/ugFZPkk","bytes":"wIGBTDs6aOvsqJfekZ0PYRT/OHyFX2TXqeNwl1SLXOI="}`,
		AssociatedData: nil,
	},
	{ // 3
		Cipher:         kes.AES256,
		Ciphertext:     string(mustDecodeB64("lbFBRVMyNTYtR0NNX1NIQTI1NtkgNjY2ODdhYWRmODYyYmQ3NzZjOGZjMThiOGU5ZjhlMjDEEExv7LAd4oz0SaHZrX5LBufEDEKME1ow1CDfUFrqv8QgJuy7Sw+jVqz99TK1HV851LT3K4mwwDv46TB2ngWkAJQ=")),
		AssociatedData: nil,
	},
	{ // 4
		Cipher:         kes.ChaCha20,
		Ciphertext:     string(mustDecodeB64("lbJYQ0hBQ0hBMjAtUE9MWTEzMDXZIDY2Njg3YWFkZjg2MmJkNzc2YzhmYzE4YjhlOWY4ZTIwxBBAr+aptD4x2+qfOhiErbnkxAxYs8RmNC1JJXD1hiHEIJ2KqM0jjkME7ndx8nyVseesN83Np0rM5ejVUun+fNFu")),
		AssociatedData: nil,
	},

	{ // 5
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // Invalid algorithm
	},
	{ // 6
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"EjOY4JKqjIrPmQ5z1KSR8zlhggY=","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid IV length
	},
	{ // 7
		Cipher:         kes.ChaCha20,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"SXAbms731/c=","bytes":"cw22HjLq/4cx8507SW4hhSrYbDiMuRao4b5+GE+XfbE="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 8
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"efY+4kYF9n8=","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid nonce length
	},
	{ // 9
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256","iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"QTza1g5oX3f9cGJMbY1xJwWPj1F7R2VnNl6XpFKYQy0="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 10
		Cipher:         kes.ChaCha20,
		Ciphertext:     `{"aead":"ChaCha20Poly1305","iv":"s3fSZ6vk5m+DfQA8yZWeUg==","nonce":"8/kHMnCMs3h9NZ2a","bytes":"TTi8pkO+Jh1JWAHvPxZeUk/iVoBPUCE4ZSVGBy3fW2s="}`,
		AssociatedData: nil,
		ShouldFail:     true, // ciphertext not authentic
	},
	{ // 11
		Cipher:         kes.AES256,
		Ciphertext:     `{"aead":"AES-256-GCM-HMAC-SHA-256" "iv":"xLxIN3tSCkg2xMafuvwUwg==","nonce":"gu0mGwUkwcvMEoi5","bytes":"WVgRjeIJm3w50C/l+y7y2i6mbNg5NCAqN1zvOYWZKmc="}`,
		AssociatedData: nil,
		ShouldFail:     true, // invalid JSON
	},
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
