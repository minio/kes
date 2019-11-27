package key

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

type sealed struct {
	Algorithm string `json:"aead"`
	IV        []byte `json:"iv"`
	Nonce     []byte `json:"nonce"`
	Bytes     []byte `json:"bytes"`
}

// Secret is a 256 bit secret key.
// It can wrap and unwrap session
// or data keys.
type Secret [32]byte

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
		algorithm = "AES-256-GCM"
	} else {
		algorithm = "ChaCha20Poly1305"
	}

	var aead cipher.AEAD
	switch algorithm {
	case "AES-256-GCM":
		var sealingKey []byte
		var block cipher.Block
		sealingKey, err = aesDeriveKey(s[:], iv)
		if err != nil {
			return nil, err
		}
		block, err = aes.NewCipher(sealingKey[:])
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
	return json.Marshal(sealed{
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
	var sealedKey sealed
	if err := json.Unmarshal(ciphertext, &sealedKey); err != nil {
		return nil, err
	}
	if n := len(sealedKey.IV); n != 16 {
		return nil, NewError(http.StatusBadRequest, "invalid iv size "+strconv.Itoa(n))
	}

	var aead cipher.AEAD
	switch sealedKey.Algorithm {
	case "AES-256-GCM":
		sealingKey, err := aesDeriveKey(s[:], sealedKey.IV)
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
		sealingKey, err := chacha20.HChaCha20(s[:], sealedKey.IV)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, NewError(http.StatusBadRequest, "invalid algorithm: "+sealedKey.Algorithm)
	}

	if n := len(sealedKey.Nonce); n != aead.NonceSize() {
		return nil, NewError(http.StatusBadRequest, "invalid nonce size "+strconv.Itoa(n))
	}
	plaintext, err := aead.Open(nil, sealedKey.Nonce, sealedKey.Bytes, associatedData)
	if err != nil {
		return nil, NewError(http.StatusBadRequest, "ciphertext is not authentic")
	}
	return plaintext, nil
}

// aesDeriveKey returns a new key derived from the
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
func aesDeriveKey(key, iv []byte) ([]byte, error) {
	if n := len(iv); n != 16 {
		return nil, errors.New("key: invalid iv size " + strconv.Itoa(n))
	}
	if n := len(key); n != 128/8 && n != 256/8 {
		return nil, aes.KeySizeError(len(key))
	}
	block, _ := aes.NewCipher(key)

	derivedKey := make([]byte, len(key))
	var v, t [aes.BlockSize]byte

	// RFC 8452 uses the entire nonce (96 bits)
	// per 64 bit derivation. Since iv is 128 bits
	// we derive the first 64 bits using the bits
	// 0..96 and the second 64 bits using the bits
	// 32..128.
	binary.LittleEndian.PutUint32(v[:4], 0)
	copy(v[4:], iv[:12])
	block.Encrypt(t[:], v[:])
	copy(derivedKey[0:], t[:8])

	binary.LittleEndian.PutUint32(v[:4], 1)
	copy(v[4:], iv[4:16])
	block.Encrypt(t[:], v[:])
	copy(derivedKey[8:], t[:8])

	if len(key) == 256/8 {
		binary.LittleEndian.PutUint32(v[:4], 2)
		copy(v[4:], iv[:12])
		block.Encrypt(t[:], v[:])
		copy(derivedKey[16:], t[:8])

		binary.LittleEndian.PutUint32(v[:4], 3)
		copy(v[4:], iv[4:16])
		block.Encrypt(t[:], v[:])
		copy(derivedKey[24:], t[:8])
	}
	return derivedKey, nil
}
