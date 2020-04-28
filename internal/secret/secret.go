// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/minio/kes"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Secret is a 256 bit cryptographic key.
// It can be used to encrypt and decrypt
// data encryption keys (DEK).
type Secret [32]byte

func ParseSecret(s string) (Secret, error) {
	type SecretJSON struct {
		Bytes []byte `json:"bytes"`
	}

	var secretJSON SecretJSON
	if err := json.NewDecoder(strings.NewReader(s)).Decode(&secretJSON); err != nil {
		return Secret{}, errors.New("secret is malformed")
	}
	if len(secretJSON.Bytes) != 32 {
		return Secret{}, errors.New("secret is malformed")
	}

	var secret Secret
	copy(secret[:], secretJSON.Bytes)
	return secret, nil
}

func (s Secret) String() string {
	return `{"bytes":"` + base64.StdEncoding.EncodeToString(s[:]) + `"}`
}

// Wrap encrypts and authenticates the plaintext,
// authenticates the associatedData and returns
// the resulting ciphertext.
//
// It should be used to encrypt a session or data
// key provided as plaintext.
//
// If the executing CPU provides AES hardware support,
// Wrap derives keys using AES and encrypts plaintexts
// using AES-GCM. Otherwise, Wrap derives keys using
// HChaCha20 and encrypts plaintexts using ChaCha20-Poly1305.
func (s Secret) Wrap(plaintext, associatedData []byte) ([]byte, error) {
	iv, err := sioutil.Random(16)
	if err != nil {
		return nil, err
	}

	var algorithm string
	if sioutil.NativeAES() {
		algorithm = "AES-256-GCM-HMAC-SHA-256"
	} else {
		algorithm = "ChaCha20Poly1305"
	}

	var aead cipher.AEAD
	switch algorithm {
	case "AES-256-GCM-HMAC-SHA-256":
		mac := hmac.New(sha256.New, s[:])
		mac.Write(iv)
		sealingKey := mac.Sum(nil)

		var block cipher.Block
		block, err = aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case "ChaCha20Poly1305":
		var sealingKey []byte
		sealingKey, err = chacha20.HChaCha20(s[:], iv)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid algorithm: " + algorithm)
	}

	nonce, err := sioutil.Random(aead.NonceSize())
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, associatedData)

	type SealedSecret struct {
		Algorithm string `json:"aead"`
		IV        []byte `json:"iv"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	return json.Marshal(SealedSecret{
		Algorithm: algorithm,
		IV:        iv,
		Nonce:     nonce,
		Bytes:     ciphertext,
	})
}

// Unwrap decrypts and verifies the ciphertext,
// verifies the associated data and, if successful,
// returns the resuting plaintext. It returns an
// error if ciphertext is malformed or not authentic.
func (s Secret) Unwrap(ciphertext []byte, associatedData []byte) ([]byte, error) {
	// TODO(aead): The Go JSON unmarshaling is malleable.
	// For instance, it ignores the first key-value pair if
	// the same key is present more than nonce or ignores
	// unknown keys by default.

	type SealedSecret struct {
		Algorithm string `json:"aead"`
		IV        []byte `json:"iv"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	var sealedSecret SealedSecret
	if err := json.Unmarshal(ciphertext, &sealedSecret); err != nil {
		return nil, err
	}
	if n := len(sealedSecret.IV); n != 16 {
		return nil, kes.NewError(http.StatusBadRequest, "invalid iv size "+strconv.Itoa(n))
	}

	var aead cipher.AEAD
	switch sealedSecret.Algorithm {
	case "AES-256-GCM-HMAC-SHA-256":
		mac := hmac.New(sha256.New, s[:])
		mac.Write(sealedSecret.IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey[:])
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case "ChaCha20Poly1305":
		sealingKey, err := chacha20.HChaCha20(s[:], sealedSecret.IV)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, kes.NewError(http.StatusBadRequest, "invalid algorithm: "+sealedSecret.Algorithm)
	}

	if n := len(sealedSecret.Nonce); n != aead.NonceSize() {
		return nil, kes.NewError(http.StatusBadRequest, "invalid nonce size "+strconv.Itoa(n))
	}
	plaintext, err := aead.Open(nil, sealedSecret.Nonce, sealedSecret.Bytes, associatedData)
	if err != nil {
		return nil, kes.NewError(http.StatusBadRequest, "ciphertext is not authentic")
	}
	return plaintext, nil
}
