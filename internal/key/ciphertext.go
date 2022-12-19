// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"encoding/json"

	"github.com/minio/kes"
	"github.com/tinylib/msgp/msgp"
)

// decodeCiphertext parses the given bytes as
// ciphertext. If it fails to unmarshal the
// given bytes, decodeCiphertext returns
// ErrDecrypt.
func decodeCiphertext(bytes []byte) (ciphertext, error) {
	if len(bytes) == 0 {
		return ciphertext{}, kes.ErrDecrypt
	}

	var c ciphertext
	switch bytes[0] {
	case 0x95: // msgp first byte
		if err := c.UnmarshalBinary(bytes); err != nil {
			return ciphertext{}, kes.ErrDecrypt
		}
	case 0x7b: // JSON first byte
		if err := c.UnmarshalJSON(bytes); err != nil {
			return ciphertext{}, kes.ErrDecrypt
		}
	default:
		if err := c.UnmarshalBinary(bytes); err != nil {
			if err = c.UnmarshalJSON(bytes); err != nil {
				return ciphertext{}, kes.ErrDecrypt
			}
		}
	}
	return c, nil
}

// ciphertext is a structure that contains the encrypted
// bytes and all relevant information to decrypt these
// bytes again with a cryptographic key.
type ciphertext struct {
	Algorithm kes.KeyAlgorithm
	ID        string
	IV        []byte
	Nonce     []byte
	Bytes     []byte
}

// MarshalBinary returns the ciphertext's binary representation.
func (c *ciphertext) MarshalBinary() ([]byte, error) {
	// We encode a ciphertext simply as message-pack
	// flat array.
	const Items = 5

	var b []byte
	b = msgp.AppendArrayHeader(b, Items)
	b = msgp.AppendString(b, c.Algorithm.String())
	b = msgp.AppendString(b, c.ID)
	b = msgp.AppendBytes(b, c.IV)
	b = msgp.AppendBytes(b, c.Nonce)
	b = msgp.AppendBytes(b, c.Bytes)
	return b, nil
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
	algorithm, b, err := msgp.ReadStringBytes(b)
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
	bytes, b, err := msgp.ReadBytesZC(b)
	if err != nil {
		return kes.ErrDecrypt
	}
	if len(b) != 0 {
		return kes.ErrDecrypt
	}

	var alg kes.KeyAlgorithm
	if err = alg.UnmarshalText([]byte(algorithm)); err != nil {
		return kes.ErrDecrypt
	}

	c.Algorithm = alg
	c.ID = id
	c.IV = iv[:]
	c.Nonce = nonce[:]
	c.Bytes = clone(bytes...)
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

	if value.Algorithm == AES256GCM {
		c.Algorithm = kes.AES256_GCM_SHA256
	} else {
		c.Algorithm = kes.XCHACHA20_POLY1305
	}
	c.ID = value.ID
	c.IV = value.IV
	c.Nonce = value.Nonce
	c.Bytes = value.Bytes
	return nil
}
