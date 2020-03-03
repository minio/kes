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
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/minio/kes"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// Secret is a 256 bit secret key.
// It can wrap and unwrap session
// or data keys.
type Secret [32]byte

// String returns the string representation
// of the secret key.
//
// It is guaranteed that the returned string
// is valid JSON.
func (s Secret) String() string {
	return fmt.Sprintf(`{"bytes":"%s"}`, base64.StdEncoding.EncodeToString(s[:]))
}

// ParseString parses v and sets the secret
// key to the parsed value, on success.
//
// ParseString will always be able to successfully
// parse a string produced by Secret.String().
func (s *Secret) ParseString(v string) error {
	const prefix = `{"bytes":"`
	const suffix = `"}`

	if !strings.HasPrefix(v, prefix) || !strings.HasSuffix(v, suffix) {
		return errors.New("secret is malformed")
	}

	v = strings.TrimPrefix(v, prefix)
	v = strings.TrimSuffix(v, suffix)

	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return errors.New("secret is malformed")
	}
	if len(b) != 32 {
		return errors.New("secret is malformed")
	}
	copy(s[:], b)
	return nil
}

func (s Secret) MarshalJSON() ([]byte, error) { return []byte(s.String()), nil }

func (s *Secret) UnmarshalJSON(b []byte) error { return s.ParseString(string(b)) }

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
	case "AES-256-GCM":
		sealingKey, err := insecureAESDeriveKey(s[:], sealedSecret.IV)
		if err != nil {
			return nil, err
		}
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

// insecureAESDeriveKey returns a new key derived from the
// provided key and iv using AES as pseudo-random-
// permutation (PRP).
// The provided key must be 16 (AES-128) or 32 (AES-256)
// bytes long and the iv must be 16 bytes long.
//
// The key deriviation is inspired by the key
// generation algorithm of AES-GCM-SIV (RFC 8452).
// See: https://tools.ietf.org/html/rfc8452#section-4)
//
// The main difference to RFC 8452 is that the iv
// is 128 bit long while AES-GCM-SIV uses 96 bit nonces.
//
// BUG(aead): The KDF implemented by insecureAESDeriveKey is
// not a PRF. The following example shows that there
// exists a relation between 4 generated keys:
//   iv0 = 0¹⁶
//   iv1 = 1 || 0¹⁵
//   iv2 = 0¹⁵ || 1
//   iv3 = 1 || 0¹⁴ || 1
// Generating 4 derived keys with these 4 iv values using
// the same key `K` gives:
//   k0 = insecureAESDeriveKey(K, iv0)
//   k1 = insecureAESDeriveKey(K, iv1)
//   k2 = insecureAESDeriveKey(K, iv2)
//   k3 = insecureAESDeriveKey(K, iv3)
// Now, the following statement holds (^ is XOR):
//   k0 ^ k1 ^ k2 == k3
// This shows that insecureAESDeriveKey is not a PRF.
func insecureAESDeriveKey(key, iv []byte) ([]byte, error) {
	if n := len(iv); n != 16 {
		return nil, errors.New("key: invalid iv size " + strconv.Itoa(n))
	}
	if n := len(key); n != 128/8 && n != 256/8 {
		return nil, aes.KeySizeError(len(key))
	}
	block, _ := aes.NewCipher(key)

	// RFC 8452 uses the entire nonce (96 bits)
	// per 64 bit derivation as following:
	//
	// k0 = E(k, 0 || nonce)[0..8]
	// k1 = E(k, 1 || nonce)[0..8]
	// k2 = E(k, 2 || nonce)[0..8]
	// k3 = E(k, 3 || nonce)[0..8]
	//
	// Since iv is 128 bits we have to ensure
	// that each 64 bit block of the key is
	// affected by all 128 iv bits. Therefore,
	// we modify the key derivation of RFC 8452
	// as following:
	//
	// t0 = E(k, 0 || iv[0..12])
	// t1 = E(k, 1 || iv[4..16])
	// t2 = E(k, 2 || iv[0..12])
	// t3 = E(k, 3 || iv[4..16])
	//
	// k0 = t0[0..8]  ^ t1[0..8]
	// k1 = t0[8..16] ^ t1[8..16]
	// k2 = t2[0..8]  ^ t3[0..8]
	// k3 = t2[8..16] ^ t3[8..16]

	derivedKey := make([]byte, len(key))
	var t0, t1 [aes.BlockSize]byte

	binary.LittleEndian.PutUint32(t0[:4], 0)
	copy(t0[4:], iv[0:12])
	binary.LittleEndian.PutUint32(t1[:4], 1)
	copy(t1[4:], iv[4:16])

	block.Encrypt(t0[:], t0[:])
	block.Encrypt(t1[:], t1[:])
	for i := range t0 {
		derivedKey[i] = t0[i] ^ t1[i]
	}

	if len(derivedKey) == 256/8 {
		var t2, t3 [aes.BlockSize]byte

		binary.LittleEndian.PutUint32(t2[:4], 2)
		copy(t2[4:], iv[0:12])
		binary.LittleEndian.PutUint32(t3[:4], 3)
		copy(t3[4:], iv[4:16])

		block.Encrypt(t2[:], t2[:])
		block.Encrypt(t3[:], t3[:])
		for i := range t2 {
			derivedKey[16+i] = t2[i] ^ t3[i]
		}
	}
	return derivedKey, nil
}
