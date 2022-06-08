// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxSize is the maximum byte size of an encoded key.
	MaxSize = 1 << 20

	// Size is the byte size of a cryptographic key.
	Size = 256 / 8
)

// ValidName returns true if and only if name is
// a valid name for a key.
func ValidName(name string) bool {
	const (
		DigitStart     = '0'
		DigitEnd       = '9'
		UpperCaseStart = 'A'
		UpperCaseEnd   = 'Z'
		LowerCaseStart = 'a'
		LowerCaseEnd   = 'z'
		Hyphen         = '-'
		Underscore     = '_'
	)
	for _, r := range name {
		switch {
		case r >= DigitStart || r <= DigitEnd:
		case r >= UpperCaseStart || r <= UpperCaseEnd:
		case r >= LowerCaseStart || r <= LowerCaseEnd:
		case r == Hyphen:
		case r == Underscore:
		default:
			return false
		}
	}
	return true
}

// Parse parses b as encoded Key.
func Parse(b []byte) (Key, error) {
	var key Key
	if err := key.UnmarshalText(b); err != nil {
		return Key{}, err
	}
	return key, nil
}

// New returns an new Key for the given cryptographic algorithm.
// The key len must match algorithm's key size. The returned key
// is owned to the specified identity.
func New(algorithm Algorithm, key []byte, owner kes.Identity) (Key, error) {
	if len(key) != algorithm.KeySize() {
		return Key{}, errors.New("key: invalid key size")
	}
	return Key{
		bytes:     clone(key...),
		algorithm: algorithm,
		createdAt: time.Now().UTC(),
		createdBy: owner,
	}, nil
}

// Random generates a new random Key for the cryptographic algorithm.
// The returned key is owned to the specified identity.
func Random(algorithm Algorithm, owner kes.Identity) (Key, error) {
	key, err := randomBytes(algorithm.KeySize())
	if err != nil {
		return Key{}, err
	}
	return New(algorithm, key, owner)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Key is a symmetric cryptographic key.
type Key struct {
	bytes []byte

	algorithm Algorithm
	createdAt time.Time
	createdBy kes.Identity
}

var (
	_ encoding.TextMarshaler     = Key{}
	_ encoding.BinaryMarshaler   = Key{}
	_ encoding.TextUnmarshaler   = (*Key)(nil)
	_ encoding.BinaryUnmarshaler = (*Key)(nil)
)

// Algorithm returns the cryptographic algorithm for which the
// key can be used.
func (k *Key) Algorithm() Algorithm { return k.algorithm }

// CreatedAt returns the point in time when the key has
// been created.
func (k *Key) CreatedAt() time.Time { return k.createdAt }

// CreatedBy returns the identity that created the key.
func (k *Key) CreatedBy() kes.Identity { return k.createdBy }

// ID returns the k's key ID.
func (k *Key) ID() string {
	const Size = 128 / 8
	h := sha256.Sum256(k.bytes)
	return hex.EncodeToString(h[:Size])
}

// Clone returns a deep copy of the key.
func (k *Key) Clone() Key {
	return Key{
		bytes:     clone(k.bytes...),
		algorithm: k.Algorithm(),
		createdAt: k.CreatedAt(),
		createdBy: k.CreatedBy(),
	}
}

// Equal returns true if and only if both keys
// are identical.
func (k *Key) Equal(other Key) bool {
	if k.Algorithm() != other.Algorithm() {
		return false
	}
	return subtle.ConstantTimeCompare(k.bytes, other.bytes) == 1
}

// MarshalText returns the key's text representation.
func (k Key) MarshalText() ([]byte, error) {
	type JSON struct {
		Bytes     []byte       `json:"bytes"`
		Algorithm Algorithm    `json:"algorithm,omitempty"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	return json.Marshal(JSON{
		Bytes:     k.bytes,
		Algorithm: k.Algorithm(),
		CreatedAt: k.CreatedAt(),
		CreatedBy: k.CreatedBy(),
	})
}

// UnmarshalText parses and decodes text as encoded key.
func (k *Key) UnmarshalText(text []byte) error {
	type JSON struct {
		Bytes     []byte       `json:"bytes"`
		Algorithm Algorithm    `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy kes.Identity `json:"created_by"`
	}
	var value JSON
	if err := json.Unmarshal(text, &value); err != nil {
		return err
	}
	k.bytes = value.Bytes
	k.algorithm = value.Algorithm
	k.createdAt = value.CreatedAt
	k.createdBy = value.CreatedBy
	return nil
}

// MarshalBinary returns the Key's binary representation.
func (k Key) MarshalBinary() ([]byte, error) {
	type GOB struct {
		Bytes     []byte
		Algorithm Algorithm
		CreatedAt time.Time
		CreatedBy kes.Identity
	}

	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(GOB{
		Bytes:     k.bytes,
		Algorithm: k.Algorithm(),
		CreatedAt: k.CreatedAt(),
		CreatedBy: k.CreatedBy(),
	})
	return buffer.Bytes(), err
}

// UnmarshalBinary unmarshals the Key's binary representation.
func (k *Key) UnmarshalBinary(b []byte) error {
	type GOB struct {
		Bytes     []byte
		Algorithm Algorithm
		CreatedAt time.Time
		CreatedBy kes.Identity
	}

	var value GOB
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&value); err != nil {
		return err
	}
	k.bytes = value.Bytes
	k.algorithm = value.Algorithm
	k.createdAt = value.CreatedAt
	k.createdBy = value.CreatedBy
	return nil
}

// Wrap encrypts the given plaintext and binds
// the associatedData to the returned ciphertext.
//
// To unwrap the ciphertext the same associatedData
// has to be provided again.
func (k *Key) Wrap(plaintext, associatedData []byte) ([]byte, error) {
	iv, err := randomBytes(16)
	if err != nil {
		return nil, err
	}

	algorithm := k.Algorithm()
	if algorithm == "" {
		if fips.Enabled || cpu.HasAESGCM() {
			algorithm = AES256_GCM_SHA256
		} else {
			algorithm = XCHACHA20_POLY1305
		}
	}
	cipher, err := newAEAD(algorithm, k.bytes, iv)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(cipher.NonceSize())
	if err != nil {
		return nil, err
	}
	ciphertext := ciphertext{
		Algorithm: algorithm,
		ID:        k.ID(),
		IV:        iv,
		Nonce:     nonce,
		Bytes:     cipher.Seal(nil, nonce, plaintext, associatedData),
	}
	return ciphertext.MarshalBinary()
}

// Unwrap decrypts the ciphertext and returns the
// resulting plaintext.
//
// It verifies that the associatedData matches the
// value used when the ciphertext has been generated.
func (k *Key) Unwrap(ciphertext, associatedData []byte) ([]byte, error) {
	text, err := decodeCiphertext(ciphertext)
	if err != nil {
		return nil, kes.ErrDecrypt
	}

	if text.ID != "" && text.ID != k.ID() { // Ciphertexts generated in the past may not contain a key ID
		return nil, kes.ErrDecrypt
	}
	if k.algorithm != "" && text.Algorithm != k.Algorithm() {
		return nil, kes.ErrDecrypt
	}

	cipher, err := newAEAD(text.Algorithm, k.bytes, text.IV)
	if err != nil {
		return nil, kes.ErrDecrypt
	}
	plaintext, err := cipher.Open(nil, text.Nonce, text.Bytes, associatedData)
	if err != nil {
		return nil, kes.ErrDecrypt
	}
	return plaintext, nil
}

// newAEAD returns a new AEAD cipher that implements the given
// algorithm and is initialized with the given key and iv.
func newAEAD(algorithm Algorithm, Key, IV []byte) (cipher.AEAD, error) {
	const (
		LEGACY_AES256_GCM_SHA256  = "AES-256-GCM-HMAC-SHA-256"
		LEGACY_XCHACHA20_POLY1305 = "ChaCha20Poly1305"
	)
	switch algorithm {
	case AES256_GCM_SHA256, LEGACY_AES256_GCM_SHA256:
		mac := hmac.New(sha256.New, Key)
		mac.Write(IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case XCHACHA20_POLY1305, LEGACY_XCHACHA20_POLY1305:
		if fips.Enabled {
			return nil, kes.ErrDecrypt
		}
		sealingKey, err := chacha20.HChaCha20(Key, IV)
		if err != nil {
			return nil, err
		}
		return chacha20poly1305.New(sealingKey)
	default:
		return nil, kes.ErrDecrypt
	}
}

func clone(b ...byte) []byte {
	c := make([]byte, 0, len(b))
	return append(c, b...)
}
