// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/minio/kes/internal/fips"
	pb "github.com/minio/kes/internal/protobuf"
	"github.com/minio/kms-go/kes"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// SecretKeySize is the size of a secret key in bytes.
const SecretKeySize = 32

// SecretKeyType defines the type of a secret key. Secret keys with
// different types are not compatible since they may differ in the
// encryption algorithm, key length, cipher mode, etc.
type SecretKeyType uint

// Supported secret key types.
const (
	// AES256 represents the AES-256-GCM secret key type.
	AES256 SecretKeyType = iota + 1

	// ChaCha20 represents the ChaCha20-Poly1305 secret key type.
	ChaCha20
)

// ParseSecretKeyType parse s as SecretKeyType string representation
// and returns an error if s is not a valid representation.
func ParseSecretKeyType(s string) (SecretKeyType, error) {
	switch s {
	case "AES256", "AES256-GCM_SHA256":
		return AES256, nil
	case "ChaCha20", "XCHACHA20-POLY1305":
		return ChaCha20, nil
	default:
		return 0, fmt.Errorf("crypto: secret key type '%s' is not supported", s)
	}
}

// String returns the string representation of the SecretKeyType.
func (s SecretKeyType) String() string {
	switch s {
	case AES256:
		return "AES256"
	case ChaCha20:
		return "ChaCha20"
	default:
		return "!INVALID:" + strconv.Itoa(int(s))
	}
}

// Supported cryptographic hash functions.
const (
	// SHA256 represents the SHA-256 hash function.
	SHA256 Hash = iota + 1
)

// Hash identifies a cryptographic hash function.
type Hash uint

// String returns the string representation of the hash function.
func (h Hash) String() string {
	switch h {
	case SHA256:
		return "SHA256"
	default:
		return "!INVALID:" + strconv.Itoa(int(h))
	}
}

// EncodeKeyVersion base64-encoded binary representation of a key.
//
// It encodes the key's binary data as base64 since some KMS keystore
// implementations do not accept or handle binary data properly.
func EncodeKeyVersion(key KeyVersion) ([]byte, error) {
	proto, err := pb.Marshal(&key)
	if err != nil {
		return nil, err
	}

	b := make([]byte, base64.StdEncoding.EncodedLen(len(proto)))
	base64.StdEncoding.Encode(b, proto)
	return b, nil
}

// ParseKeyVersion parses b as ParseKeyVersion.
func ParseKeyVersion(b []byte) (KeyVersion, error) {
	if json.Valid(b) {
		type JSON struct {
			Bytes     []byte       `json:"bytes"`
			Type      string       `json:"algorithm"`
			CreatedAt time.Time    `json:"created_at"`
			CreatedBy kes.Identity `json:"created_by"`
		}

		var value JSON
		if err := json.Unmarshal(b, &value); err != nil {
			return KeyVersion{}, err
		}

		var cipher SecretKeyType
		if value.Type == "" {
			cipher = AES256
		} else {
			var err error
			if cipher, err = ParseSecretKeyType(value.Type); err != nil {
				return KeyVersion{}, err
			}
		}
		key, err := NewSecretKey(cipher, value.Bytes)
		if err != nil {
			return KeyVersion{}, err
		}

		return KeyVersion{
			Key:       key,
			CreatedAt: value.CreatedAt,
			CreatedBy: value.CreatedBy,
		}, nil
	}

	raw, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return KeyVersion{}, err
	}

	var key KeyVersion
	if err := pb.Unmarshal(raw, &key); err != nil {
		return KeyVersion{}, err
	}
	return key, nil
}

// KeyVersion represents a version of a secret key.
type KeyVersion struct {
	Key       SecretKey    // The secret key
	HMACKey   HMACKey      // The HMAC key
	CreatedAt time.Time    // The creation timestamp of the key version
	CreatedBy kes.Identity // The identity of the entity that created the key version
}

// HasHMACKey reports whether the KeyVersion has an HMAC key.
//
// Keys created in the past did not generate a HMAC key.
func (s *KeyVersion) HasHMACKey() bool {
	return s.HMACKey.initialized
}

// MarshalPB converts the KeyVersion into its protobuf representation.
func (s *KeyVersion) MarshalPB(v *pb.KeyVersion) error {
	v.Key, v.HMACKey = &pb.SecretKey{}, &pb.HMACKey{}
	if err := s.Key.MarshalPB(v.Key); err != nil {
		return err
	}
	if err := s.HMACKey.MarshalPB(v.HMACKey); err != nil {
		return err
	}

	v.CreatedAt = pb.Time(s.CreatedAt)
	v.CreatedBy = s.CreatedBy.String()
	return nil
}

// UnmarshalPB initializes the KeyVersion from its protobuf representation.
func (s *KeyVersion) UnmarshalPB(v *pb.KeyVersion) error {
	var (
		key     SecretKey
		hmacKey HMACKey
	)
	if err := key.UnmarshalPB(v.Key); err != nil {
		return err
	}
	if err := hmacKey.UnmarshalPB(v.HMACKey); err != nil {
		return err
	}

	s.Key = key
	s.HMACKey = hmacKey
	s.CreatedAt = v.CreatedAt.AsTime()
	s.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

// NewSecretKey creates a new SecretKey with the specified cipher and key.
//
// The key must be SecretKeySize bytes long.
func NewSecretKey(cipher SecretKeyType, key []byte) (SecretKey, error) {
	if n := len(key); n != SecretKeySize {
		return SecretKey{}, fmt.Errorf("crypto: invalid key length '%d' for '%s'", n, cipher)
	}

	return SecretKey{
		cipher:      cipher,
		key:         [SecretKeySize]byte(key),
		initialized: true,
	}, nil
}

// GenerateSecretKey generates a new random SecretKey with the specified
// cipher.
//
// If random is nil the standard library crypto/rand.Reader is used.
func GenerateSecretKey(cipher SecretKeyType, random io.Reader) (SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var bytes [SecretKeySize]byte
	if _, err := io.ReadFull(random, bytes[:]); err != nil {
		return SecretKey{}, err
	}
	return NewSecretKey(cipher, bytes[:])
}

// SecretKey represents a secret key used for encryption and decryption.
type SecretKey struct {
	cipher SecretKeyType
	key    [SecretKeySize]byte

	initialized bool
}

const randSize = 28

// Type returns the SecretKey's type.
func (s SecretKey) Type() SecretKeyType { return s.cipher }

// Overhead returns the size difference between a plaintext
// and its ciphertext.
func (s SecretKey) Overhead() int { return randSize + 16 }

// Bytes returns the raw key bytes.
func (s SecretKey) Bytes() []byte {
	b := make([]byte, 0, len(s.key))
	return append(b, s.key[:]...)
}

// Encrypt encrypts and authenticates the plaintext and
// authenticates the associatedData.
//
// The same associatedData must be provided when decrypting.
func (s SecretKey) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if !s.initialized {
		panic("crypto: usage of empty or uninitialized secret key")
	}
	if fips.Enabled {
		if s.cipher != AES256 {
			return nil, errors.New("crypto: cipher not available in FIPS mode")
		}
	}

	var random [randSize]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	iv, nonce := random[:16], random[16:]

	var aead cipher.AEAD
	switch s.cipher {
	case AES256:
		prf := hmac.New(sha256.New, s.key[:])
		prf.Write(iv)
		key := prf.Sum(make([]byte, 0, prf.Size()))

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case ChaCha20:
		key, err := chacha20.HChaCha20(s.key[:], iv)
		if err != nil {
			return nil, err
		}
		c, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		aead = c
	default:
		panic("crypto: unknown secret key cipher '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	ciphertext := extend(plaintext, s.Overhead())
	ciphertext = aead.Seal(ciphertext[:0], nonce, plaintext, associatedData)
	ciphertext = append(ciphertext, random[:]...)
	return ciphertext, nil
}

// Decrypt decrypts and authenticates the ciphertext and
// authenticates the associatedData.
//
// The same associatedData used during encryption must be
// provided.
func (s SecretKey) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	if !s.initialized {
		panic("crypto: usage of empty or uninitialized secret key detected")
	}
	if fips.Enabled {
		if s.cipher != AES256 {
			return nil, errors.New("crypto: cipher not available in FIPS mode")
		}
	}
	ciphertext = parseCiphertext(ciphertext) // handle previous ciphertext formats

	if len(ciphertext) <= randSize {
		return nil, kes.ErrDecrypt
	}
	ciphertext, random := ciphertext[:len(ciphertext)-randSize], ciphertext[len(ciphertext)-randSize:]
	iv, nonce := random[:16], random[16:]

	var aead cipher.AEAD
	switch s.cipher {
	case AES256:
		prf := hmac.New(sha256.New, s.key[:])
		prf.Write(iv)
		key := prf.Sum(make([]byte, 0, prf.Size()))

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case ChaCha20:
		key, err := chacha20.HChaCha20(s.key[:], iv)
		if err != nil {
			return nil, err
		}
		c, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		aead = c
	default:
		panic("crypto: unknown secret key type '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	plaintext, err := aead.Open(ciphertext[:0], nonce, ciphertext, associatedData)
	if err != nil {
		return nil, kes.ErrDecrypt
	}
	return plaintext, nil
}

// MarshalPB converts the SecretKey into its protobuf representation.
func (s *SecretKey) MarshalPB(v *pb.SecretKey) error {
	if !s.initialized {
		return errors.New("crypto: secret key is not initialized")
	}
	if s.cipher != AES256 && s.cipher != ChaCha20 {
		return errors.New("crypto: invalid secret key type '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	v.Key = slices.Clone(s.key[:])
	v.Type = uint32(s.cipher)
	return nil
}

// UnmarshalPB initializes the SecretKey from its protobuf representation.
func (s *SecretKey) UnmarshalPB(v *pb.SecretKey) error {
	if n := len(v.Key); n != SecretKeySize {
		return errors.New("crypto: invalid secret key length '" + strconv.Itoa(n) + "'")
	}
	if t := SecretKeyType(v.Type); t != AES256 && t != ChaCha20 {
		return errors.New("crypto: invalid secret key type '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	s.key = [SecretKeySize]byte(v.Key)
	s.cipher = SecretKeyType(v.Type)
	s.initialized = true
	return nil
}

// NewHMACKey creates a new HMACKey with the specified hash function and key.
//
// The key must be 32 bytes long.
func NewHMACKey(hash Hash, key []byte) (HMACKey, error) {
	if n := len(key); n != 32 {
		return HMACKey{}, fmt.Errorf("crypto: invalid key length '%d' for '%s'", n, hash)
	}

	return HMACKey{
		hash:        hash,
		key:         [32]byte(key),
		initialized: true,
	}, nil
}

// GenerateHMACKey generates a new random HMACKey with the specified hash function.
//
// If random is nil the standard library crypto/rand.Reader is used.
func GenerateHMACKey(hash Hash, random io.Reader) (HMACKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var bytes [32]byte
	if _, err := io.ReadFull(random, bytes[:]); err != nil {
		return HMACKey{}, err
	}
	return NewHMACKey(hash, bytes[:])
}

// HMACKey represents a secret key used for computing HMAC checksums.
type HMACKey struct {
	key  [32]byte
	hash Hash

	initialized bool
}

// Type returns the HMACKey's hash function.
func (k HMACKey) Type() Hash { return k.hash }

// Sum computes and returns the HMAC checksum of msg.
func (k *HMACKey) Sum(msg []byte) []byte {
	if !k.initialized {
		panic("crypto: usage of empty or uninitialized HMAC key detected")
	}

	switch k.hash {
	case SHA256:
		mac := hmac.New(sha256.New, k.key[:])
		mac.Write(msg)
		return mac.Sum(make([]byte, 0, mac.Size()))
	default:
		panic("crypto: unknown HMAC key hash '" + strconv.Itoa(int(k.hash)) + "'")
	}
}

// Equal reports whether mac1 and mac2 are equal without
// leaking any timing information.
func (k *HMACKey) Equal(mac1, mac2 []byte) bool {
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}

// MarshalPB converts the HMACKey into its protobuf representation.
func (k *HMACKey) MarshalPB(v *pb.HMACKey) error {
	if !k.initialized {
		return errors.New("crypto: HMAC key is not initialized")
	}
	if k.hash != SHA256 {
		return errors.New("crypto: invalid HMAC key hash '" + strconv.Itoa(int(k.hash)) + "'")
	}

	v.Key = slices.Clone(k.key[:])
	v.Hash = uint32(k.hash)
	return nil
}

// UnmarshalPB initializes the HMACKey from its protobuf representation.
func (k *HMACKey) UnmarshalPB(v *pb.HMACKey) error {
	if n := len(v.Key); n != 32 {
		return errors.New("crypto: invalid HMAC key length '" + strconv.Itoa(n) + "'")
	}
	if Hash(v.Hash) != SHA256 {
		return errors.New("crypto: invalid HMAC key hash '" + strconv.Itoa(int(k.hash)) + "'")
	}

	k.key = [32]byte(v.Key)
	k.hash = Hash(v.Hash)
	k.initialized = true
	return nil
}

func extend(b []byte, n int) []byte {
	total := len(b) + n
	if cap(b) >= total {
		return b[:total]
	}

	c := make([]byte, total)
	copy(c, b)
	return c
}
