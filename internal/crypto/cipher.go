package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	AES_256_GCM      algorithm = "AES-256-GCM"
	ChaCha20Poly1305 algorithm = "ChaCha20Poly1305"
)

type algorithm string

func (a algorithm) New(key []byte) (cipher.AEAD, error) {
	switch a {
	case AES_256_GCM:
		if len(key) != AES_256_GCM.KeySize() {
			return nil, aes.KeySizeError(len(key))
		}
		block, _ := aes.NewCipher(key) // block is never nil since we checked the key size
		return cipher.NewGCM(block)
	case ChaCha20Poly1305:
		return chacha20poly1305.New(key)
	default:
		panic(fmt.Sprintf("internal/crypto: unknown cipher '%s'", a.String()))
	}
}

func (a algorithm) KeySize() int { return 256 / 8 }

func (a algorithm) NonceSize() int { return 96 / 8 }

func (a algorithm) String() string { return string(a) }

func ParseAlgorithm(s string) (algorithm, error) {
	switch s {
	case AES_256_GCM.String():
		return AES_256_GCM, nil
	case ChaCha20Poly1305.String():
		return ChaCha20Poly1305, nil
	default:
		return "", fmt.Errorf("internal/crypto: unknown cipher '%s'", s)
	}
}
