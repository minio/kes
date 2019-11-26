package key

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"

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

type Secret [32]byte

func (s Secret) Wrap(plaintext, associatedData []byte) ([]byte, error) {
	iv, err := sioutil.Random(16)
	if err != nil {
		return nil, err
	}

	var algorithm string
	var aead cipher.AEAD
	if sioutil.NativeAES() {
		algorithm = "AES-256-GCM"
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
	} else {
		algorithm = "ChaCha20Poly1305"
		var sealingKey []byte
		sealingKey, err = chacha20.HChaCha20(s[:], iv)
		if err != nil {
			return nil, err
		}
		aead, err = chacha20poly1305.New(sealingKey)
		if err != nil {
			return nil, err
		}
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

func (s Secret) Unwrap(ciphertext []byte, associatedData []byte) ([]byte, error) {
	var sealedKey sealed
	if err := json.Unmarshal(ciphertext, &sealedKey); err != nil {
		return nil, err
	}
	if len(sealedKey.IV) != 16 {
		return nil, errors.New("invalid IV")
	}

	var aead cipher.AEAD
	switch sealedKey.Algorithm {
	default:
		return nil, errors.New("invalid algorithm")
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
	}
	if len(sealedKey.Nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	return aead.Open(nil, sealedKey.Nonce, sealedKey.Bytes, associatedData)
}

func aesDeriveKey(key, iv []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid key")
	}
	if len(iv) != 16 {
		return nil, errors.New("invalid IV")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var derived [32]byte
	var v, t [aes.BlockSize]byte
	binary.LittleEndian.PutUint32(v[:4], 0)
	copy(v[4:], iv[:12])
	block.Encrypt(t[:], v[:])
	copy(derived[0:], t[:8])

	binary.LittleEndian.PutUint32(v[:4], 1)
	copy(v[4:], iv[4:])
	block.Encrypt(t[:], v[:])
	copy(derived[8:], t[:8])

	binary.LittleEndian.PutUint32(v[:4], 2)
	copy(v[4:], iv[:12])
	block.Encrypt(t[:], v[:])
	copy(derived[16:], t[:8])

	binary.LittleEndian.PutUint32(v[:4], 3)
	copy(v[4:], iv[4:])
	block.Encrypt(t[:], iv)
	copy(derived[24:], t[:8])
	return derived[:], nil
}
