package key

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/fips"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// MaxSize is the maximum byte size of an encoded key.
	MaxSize = 1 << 20

	// Size is the byte size of a cryptographic key.
	Size = 256 / 8
)

// Key is a secret key for symmetric cryptography.
type Key struct {
	bytes []byte
}

// New returns a new key for symmetric cryptography.
func New(bytes []byte) Key {
	return Key{
		bytes: clone(bytes...),
	}
}

// Parse parses s as encoded secret key.
func Parse(s string) (Key, error) {
	type JSON struct {
		Bytes []byte `json:"bytes"`
	}
	var key JSON
	if err := json.NewDecoder(strings.NewReader(s)).Decode(&key); err != nil {
		return Key{}, errors.New("key: key is malformed")
	}
	if len(key.Bytes) != 256/8 { // Only accept 256 bit keys
		return Key{}, errors.New("key: key is malformed")
	}
	return New(key.Bytes), nil
}

// ID returns the k's key ID.
func (k Key) ID() string {
	const Size = 128 / 8
	h := sha256.Sum256(k.bytes)
	return hex.EncodeToString(h[:Size])
}

// Equal returns true if and only if both keys
// are identical.
func (k Key) Equal(other Key) bool { return subtle.ConstantTimeCompare(k.bytes, other.bytes) == 1 }

// String returns k's string representation.
func (k Key) String() string {
	return fmt.Sprintf(`{"bytes":"%s"}`, base64.StdEncoding.EncodeToString(k.bytes))
}

// Wrap encrypts the given plaintext with k and binds
// the associatedData to the returned ciphertext.
//
// To unwrap the ciphertext the same associatedData
// has to be provided again.
func (k Key) Wrap(plaintext, associatedData []byte) ([]byte, error) {
	iv, err := sioutil.Random(16)
	if err != nil {
		return nil, err
	}

	var algorithm string
	if fips.Enabled || sioutil.NativeAES() {
		algorithm = "AES-256-GCM-HMAC-SHA-256"
	} else {
		algorithm = "ChaCha20Poly1305"
	}

	var aead cipher.AEAD
	switch algorithm {
	case "AES-256-GCM-HMAC-SHA-256":
		mac := hmac.New(sha256.New, k.bytes)
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
		sealingKey, err = chacha20.HChaCha20(k.bytes, iv)
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
	type SealedKey struct {
		Algorithm string `json:"aead"`
		ID        string `json:"id,omitempty"`
		IV        []byte `json:"iv"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	return json.Marshal(SealedKey{
		Algorithm: algorithm,
		ID:        k.ID(),
		IV:        iv,
		Nonce:     nonce,
		Bytes:     ciphertext,
	})
}

// Unwrap decrypts the ciphertext using k and returns
// the resulting plaintext.
//
// It verifies that the associatedData matches the
// value used when the ciphertext has been generated.
func (k Key) Unwrap(ciphertext, associatedData []byte) ([]byte, error) {
	type SealedKey struct {
		Algorithm string `json:"aead"`
		ID        string `json:"id"`
		IV        []byte `json:"iv"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	var sealedKey SealedKey
	if err := json.Unmarshal(ciphertext, &sealedKey); err != nil {
		return nil, kes.NewError(http.StatusBadRequest, "invalid ciphertext")
	}
	if sealedKey.ID != "" && sealedKey.ID != k.ID() { // Ciphertexts generated in the past may not contain a key ID
		return nil, kes.NewError(http.StatusBadRequest, "invalid ciphertext: key ID mismatch")
	}
	if n := len(sealedKey.IV); n != 16 {
		return nil, kes.NewError(http.StatusBadRequest, "invalid iv size")
	}

	var aead cipher.AEAD
	switch {
	case sealedKey.Algorithm == "AES-256-GCM-HMAC-SHA-256":
		mac := hmac.New(sha256.New, k.bytes)
		mac.Write(sealedKey.IV)
		sealingKey := mac.Sum(nil)

		block, err := aes.NewCipher(sealingKey[:])
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	case !fips.Enabled && sealedKey.Algorithm == "ChaCha20Poly1305":
		sealingKey, err := chacha20.HChaCha20(k.bytes, sealedKey.IV)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, kes.NewError(http.StatusUnprocessableEntity, "unsupported cryptographic algorithm")
	}

	if n := len(sealedKey.Nonce); n != aead.NonceSize() {
		return nil, kes.NewError(http.StatusBadRequest, "invalid nonce size")
	}
	plaintext, err := aead.Open(nil, sealedKey.Nonce, sealedKey.Bytes, associatedData)
	if err != nil {
		return nil, kes.ErrDecrypt
	}
	return plaintext, nil
}

// ID returns the ID of the key used to generate
// the ciphertext.
func ID(ciphertext []byte) string {
	type JSON struct {
		ID string `json:"id"`
	}
	var key JSON
	if err := json.Unmarshal(ciphertext, &key); err != nil {
		return ""
	}
	return key.ID
}

func clone(b ...byte) []byte {
	c := make([]byte, 0, len(b))
	return append(c, b...)
}
