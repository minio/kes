// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"strconv"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/msgp"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// SecretKeySize represents the size of a secret key in bytes.
const SecretKeySize = 32

// MaxSecretKeyVersions specifies the maximum number of concurrent
// versions for a key ring.
const MaxSecretKeyVersions = 10000

// SecretKeyCipher represents the encryption algorithm used for
// secret key operations.
type SecretKeyCipher uint

// Secret key encryption algorithms.
const (
	// AES256 represents the AES-256-GCM encryption algorithm.
	AES256 SecretKeyCipher = iota

	// ChaCha20 represents the ChaCha20-Poly1305 encryption algorithm.
	ChaCha20
)

const randSize = 28

// SecretKeyRing represents collection of secret key versions.
type SecretKeyRing struct {
	versions  map[uint32]SecretKeyVersion
	n, latest uint32
}

// Latest returns the latest secret key version and its corresponding
// version number.
func (s *SecretKeyRing) Latest() (SecretKeyVersion, uint32) {
	return s.versions[s.latest], s.latest
}

// Get retrieves a specific secret key version based on its version number.
// It returns false if the version does not exist.
func (s *SecretKeyRing) Get(version uint32) (SecretKeyVersion, bool) {
	v, ok := s.versions[version]
	return v, ok
}

// Add adds a new secret key version to the key ring.
//
// In total, at most 2^32 - 1 versions can be added to
// a key ring. Once this limit has been reached, no more
// versions can be added.
//
// A key ring can hold up to MaxSecretKeyVersions at the
// same time. Once its max. capacity has been reached,
// secret key versions must be removed before new versions
// can be added again.
func (s *SecretKeyRing) Add(version SecretKeyVersion) error {
	if s.latest == math.MaxUint32 {
		return errors.New("crypto: no more secret key versions available")
	}
	if len(s.versions) >= MaxSecretKeyVersions {
		return errors.New("crypto: too many secret key versions")
	}

	if s.versions == nil {
		s.versions = make(map[uint32]SecretKeyVersion)
	}
	s.versions[s.n] = version
	s.latest = s.n
	s.n++
	return nil
}

// MarshalMsg converts the SecretKeyRing into its MessagePack representation.
func (s *SecretKeyRing) MarshalMsg() (msgp.SecretKeyRing, error) {
	versions := make(map[string]msgp.SecretKeyVersion, len(s.versions))
	for k, v := range s.versions {
		key, err := v.Key.MarshalMsg()
		if err != nil {
			return msgp.SecretKeyRing{}, err
		}
		versions[strconv.Itoa(int(k))] = msgp.SecretKeyVersion{
			Key:       key,
			CreatedAt: v.CreatedAt,
			CreatedBy: v.CreatedBy.String(),
		}
	}
	return msgp.SecretKeyRing{
		Versions: versions,
		N:        s.n,
		Latest:   s.latest,
	}, nil
}

// UnmarshalMsg initializes the SecretKeyRing from its MessagePack representation.
func (s *SecretKeyRing) UnmarshalMsg(ring *msgp.SecretKeyRing) error {
	versions := make(map[uint32]SecretKeyVersion, len(ring.Versions))
	for k, v := range ring.Versions {
		version, err := strconv.Atoi(k)
		if err != nil {
			return err
		}
		if version > math.MaxUint32 {
			return errors.New("crypto: secret key version overflow")
		}

		var key SecretKey
		if err := key.UnmarshalMsg(&v.Key); err != nil {
			return err
		}

		versions[uint32(version)] = SecretKeyVersion{
			Key:       key,
			CreatedAt: v.CreatedAt,
			CreatedBy: kes.Identity(v.CreatedBy),
		}
	}

	s.versions = versions
	s.latest = ring.Latest
	s.n = ring.N
	return nil
}

// SecretKeyVersion represents a version of a secret key.
type SecretKeyVersion struct {
	Key       SecretKey    // The secret key
	CreatedAt time.Time    // The creation timestamp of the key version
	CreatedBy kes.Identity // The identity of the entity that created the key version
}

// MarshalMsg converts the SecretKeyVersion into its MessagePack representation.
func (s *SecretKeyVersion) MarshalMsg() (msgp.SecretKeyVersion, error) {
	key, err := s.Key.MarshalMsg()
	if err != nil {
		return msgp.SecretKeyVersion{}, err
	}
	return msgp.SecretKeyVersion{
		Key:       key,
		CreatedAt: s.CreatedAt,
		CreatedBy: s.CreatedBy.String(),
	}, nil
}

// UnmarshalMsg initializes the SecretKeyVersion from its MessagePack representation.
func (s *SecretKeyVersion) UnmarshalMsg(v *msgp.SecretKeyVersion) error {
	var key SecretKey
	if err := key.UnmarshalMsg(&v.Key); err != nil {
		return err
	}

	s.Key = key
	s.CreatedAt = v.CreatedAt
	s.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}

// SecretKey represents a secret key used for encryption and decryption.
type SecretKey struct {
	cipher SecretKeyCipher
	key    [32]byte

	initialized bool
}

// NewSecretKey creates a new SecretKey with the specified cipher and key.
//
// The key must be SecretKeySize bytes long.
func NewSecretKey(cipher SecretKeyCipher, key []byte) (SecretKey, error) {
	if n := len(key); n != SecretKeySize {
		return SecretKey{}, errors.New("crypto: invalid secret key length '" + strconv.Itoa(n) + "'")
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
func GenerateSecretKey(cipher SecretKeyCipher, random io.Reader) (SecretKey, error) {
	if random == nil {
		random = rand.Reader
	}

	bytes := make([]byte, SecretKeySize)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return SecretKey{}, err
	}
	return NewSecretKey(cipher, bytes)
}

// Overhead returns the size difference between a plaintext
// and its ciphertext.
func (s SecretKey) Overhead() int { return randSize + 16 }

// Encrypt encrypts and authenticates the plaintext and
// authenticates the associatedData.
//
// The same associatedData must be provided when decrypting.
func (s SecretKey) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if !s.initialized {
		panic("crypto: usage of empty or uninitialized secret key")
	}
	if fips.Mode != fips.ModeNone {
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

		block, err := aes.NewCipher(key[:])
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
		c, err := chacha20poly1305.New(key[:])
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
	if fips.Mode != fips.ModeNone {
		if s.cipher != AES256 {
			return nil, errors.New("crypto: cipher not available in FIPS mode")
		}
	}

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

		block, err := aes.NewCipher(key[:])
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
		c, err := chacha20poly1305.New(key[:])
		if err != nil {
			return nil, err
		}
		aead = c
	default:
		panic("crypto: unknown secret key cipher '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	plaintext, err := aead.Open(ciphertext[:0], nonce[:], ciphertext, associatedData)
	if err != nil {
		return nil, kes.ErrDecrypt
	}
	return plaintext, nil
}

// MarshalMsg converts the SecretKey into its MessagePack representation.
func (s *SecretKey) MarshalMsg() (msgp.SecretKey, error) {
	if !s.initialized {
		return msgp.SecretKey{}, errors.New("crypto: secret key is not initialized")
	}
	return msgp.SecretKey{
		Value:  s.key[:],
		Cipher: uint(s.cipher),
	}, nil
}

// UnmarshalMsg initializes the SecretKey from its MessagePack representation.
func (s *SecretKey) UnmarshalMsg(v *msgp.SecretKey) error {
	if n := len(v.Value); n != SecretKeySize {
		return errors.New("crypto: invalid secret key length '" + strconv.Itoa(n) + "'")
	}
	if s.cipher != AES256 && s.cipher != ChaCha20 {
		return errors.New("crypto: invalid secret key cipher '" + strconv.Itoa(int(s.cipher)) + "'")
	}

	s.key = [SecretKeySize]byte(v.Value)
	s.cipher = SecretKeyCipher(v.Cipher)
	s.initialized = true
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
