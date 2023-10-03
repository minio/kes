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
	"fmt"
	"time"

	"github.com/minio/kes-go"
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

// Parse parses b as encoded Key.
func Parse(b []byte) (Key, error) {
	var key Key
	if err := key.UnmarshalText(b); err != nil {
		return Key{}, err
	}
	return key, nil
}

// Len returns the length of keys for the given Algorithm in bytes.
func Len(a kes.KeyAlgorithm) int {
	switch a {
	case kes.AES256:
		return 256 / 8
	case kes.ChaCha20:
		return 256 / 8
	default:
		fmt.Println(int(a))
		return -1
	}
}

// New returns an new Key for the given cryptographic algorithm.
// The key len must match algorithm's key size. The returned key
// is owned to the specified identity.
func New(algorithm kes.KeyAlgorithm, key []byte, owner kes.Identity) (Key, error) {
	if len(key) != Len(algorithm) {
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
func Random(algorithm kes.KeyAlgorithm, owner kes.Identity) (Key, error) {
	key, err := randomBytes(Len(algorithm))
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

	algorithm kes.KeyAlgorithm
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
func (k *Key) Algorithm() kes.KeyAlgorithm { return k.algorithm }

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
		Version   version          `json:"version"`
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time        `json:"created_at,omitempty"`
		CreatedBy kes.Identity     `json:"created_by,omitempty"`
	}
	return json.Marshal(JSON{
		Version:   v1,
		Bytes:     k.bytes,
		Algorithm: k.Algorithm(),
		CreatedAt: k.CreatedAt(),
		CreatedBy: k.CreatedBy(),
	})
}

// UnmarshalText parses and decodes text as encoded key.
func (k *Key) UnmarshalText(text []byte) error {
	type JSON struct {
		Version   version          `json:"version"`
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time        `json:"created_at"`
		CreatedBy kes.Identity     `json:"created_by"`
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
		Version   version
		Bytes     []byte
		Algorithm kes.KeyAlgorithm
		CreatedAt time.Time
		CreatedBy kes.Identity
	}

	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(GOB{
		Version:   v1,
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
		Version   version
		Bytes     []byte
		Algorithm kes.KeyAlgorithm
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
func newAEAD(algorithm kes.KeyAlgorithm, Key, IV []byte) (cipher.AEAD, error) {
	switch algorithm {
	case kes.AES256:
		mac := hmac.New(sha256.New, Key)
		mac.Write(IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case kes.ChaCha20:
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
