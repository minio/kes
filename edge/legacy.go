// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/crypto"
	msgp2 "github.com/minio/kes/internal/msgp"
	"github.com/tinylib/msgp/msgp"
)

func parseSecretKeyVersion(data []byte) (crypto.SecretKeyVersion, error) {
	if !json.Valid(data) {
		var key crypto.SecretKeyVersion
		if err := msgp2.Unmarshal(data, &key); err != nil {
			return crypto.SecretKeyVersion{}, err
		}
		return key, nil
	}

	var value struct {
		Bytes     []byte       `json:"bytes"`
		Algorithm string       `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy kes.Identity `json:"created_by"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return crypto.SecretKeyVersion{}, err
	}

	var cipher crypto.SecretKeyCipher
	switch value.Algorithm {
	case "AES256-GCM_SHA256":
		cipher = crypto.AES256
	case "XCHACHA20-POLY1305":
		cipher = crypto.ChaCha20
	default:
		return crypto.SecretKeyVersion{}, errors.New("keystore: invalid key algorithm '" + value.Algorithm + "'")
	}

	key, err := crypto.NewSecretKey(cipher, value.Bytes)
	if err != nil {
		return crypto.SecretKeyVersion{}, err
	}
	return crypto.SecretKeyVersion{
		Key:       key,
		CreatedAt: value.CreatedAt,
		CreatedBy: value.CreatedBy,
	}, nil
}

// decodeCiphertext parses the given bytes as
// ciphertext. If it fails to unmarshal the
// given bytes, decodeCiphertext returns
// ErrDecrypt.
func decodeCiphertext(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	var c ciphertext
	switch data[0] {
	case 0x95: // msgp first byte
		if err := c.UnmarshalBinary(data); err != nil {
			return data, nil
		}
	case 0x7b: // JSON first byte
		if err := c.UnmarshalJSON(data); err != nil {
			return data, nil
		}
	default:
		return data, nil
	}

	text := make([]byte, 0, len(c.Bytes)+16+12)
	text = append(text, c.Bytes...)
	text = append(text, c.IV...)
	text = append(text, c.Nonce...)
	return text, nil
}

// ciphertext is a structure that contains the encrypted
// bytes and all relevant information to decrypt these
// bytes again with a cryptographic key.
type ciphertext struct {
	ID    string
	IV    []byte
	Nonce []byte
	Bytes []byte
}

// UnmarshalBinary parses b as binary-encoded ciphertext.
func (c *ciphertext) UnmarshalBinary(b []byte) error {
	const (
		Items     = 5
		IVSize    = 16
		NonceSize = 12
	)

	items, b, err := msgp.ReadArrayHeaderBytes(b)
	if err != nil {
		return kes.ErrDecrypt
	}
	if items != Items {
		return kes.ErrDecrypt
	}
	_, b, err = msgp.ReadStringBytes(b)
	if err != nil {
		return kes.ErrDecrypt
	}
	id, b, err := msgp.ReadStringBytes(b)
	if err != nil {
		return kes.ErrDecrypt
	}
	var iv [IVSize]byte
	b, err = msgp.ReadExactBytes(b, iv[:])
	if err != nil {
		return kes.ErrDecrypt
	}
	var nonce [NonceSize]byte
	b, err = msgp.ReadExactBytes(b, nonce[:])
	if err != nil {
		return kes.ErrDecrypt
	}
	data, b, err := msgp.ReadBytesZC(b)
	if err != nil {
		return kes.ErrDecrypt
	}
	if len(b) != 0 {
		return kes.ErrDecrypt
	}

	c.ID = id
	c.IV = iv[:]
	c.Nonce = nonce[:]
	c.Bytes = bytes.Clone(data)
	return nil
}

// UnmarshalJSON parses the given text as JSON-encoded
// ciphertext.
//
// UnmarshalJSON provides backward-compatible unmarsahaling
// of existing ciphertext. In the past, ciphertexts were
// JSON-encoded. Now, ciphertexts are binary-encoded.
// Therefore, there is no MarshalJSON implementation.
func (c *ciphertext) UnmarshalJSON(text []byte) error {
	const (
		IVSize    = 16
		NonceSize = 12

		AES256GCM        = "AES-256-GCM-HMAC-SHA-256"
		CHACHA20POLY1305 = "ChaCha20Poly1305"
	)

	type JSON struct {
		Algorithm string `json:"aead"`
		ID        string `json:"id,omitempty"`
		IV        []byte `json:"iv"`
		Nonce     []byte `json:"nonce"`
		Bytes     []byte `json:"bytes"`
	}
	var value JSON
	if err := json.Unmarshal(text, &value); err != nil {
		return kes.ErrDecrypt
	}

	if value.Algorithm != AES256GCM && value.Algorithm != CHACHA20POLY1305 {
		return kes.ErrDecrypt
	}
	if len(value.IV) != IVSize {
		return kes.ErrDecrypt
	}
	if len(value.Nonce) != NonceSize {
		return kes.ErrDecrypt
	}

	c.ID = value.ID
	c.IV = value.IV
	c.Nonce = value.Nonce
	c.Bytes = value.Bytes
	return nil
}
