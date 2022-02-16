// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// DEK is a data encryption key. It has a plaintext
// and a ciphertext representation.
//
// Applications should use the plaintext for cryptographic
// operations and store the ciphertext at a durable
// location.
//
// If the DEK is used to e.g. encrypt some data then it's
// safe to store the DEK's ciphertext representation next
// to the encrypted data. The ciphertext representation
// does not need to stay secret.
//
// DEK implements binary as well as text marshaling.
// However, only the ciphertext representation gets
// encoded. The plaintext should never be stored
// anywhere.
// Therefore, after un-marshaling there will be no
// plaintext representation. To obtain it the
// ciphertext must be decrypted.
type DEK struct {
	Plaintext  []byte
	Ciphertext []byte
}

var (
	_ encoding.BinaryMarshaler   = (*DEK)(nil)
	_ encoding.TextMarshaler     = (*DEK)(nil)
	_ encoding.BinaryUnmarshaler = (*DEK)(nil)
	_ encoding.TextUnmarshaler   = (*DEK)(nil)
)

// MarshalText encodes the DEK's ciphertext into
// a base64-encoded text and returns the result.
//
// It never returns an error.
func (d DEK) MarshalText() ([]byte, error) {
	ciphertext := make([]byte, base64.StdEncoding.EncodedLen(len(d.Ciphertext)))
	base64.StdEncoding.Encode(ciphertext, d.Ciphertext)
	return ciphertext, nil
}

// UnmarshalText tries to decode a base64-encoded text
// and sets DEK's ciphertext to the decoded data.
//
// It returns an error if text is not base64-encoded.
//
// UnmarshalText sets DEK's plaintext to nil.
func (d *DEK) UnmarshalText(text []byte) (err error) {
	n := base64.StdEncoding.DecodedLen(len(text))
	if len(d.Ciphertext) < n {
		if cap(d.Ciphertext) >= n {
			d.Ciphertext = d.Ciphertext[:n]
		} else {
			d.Ciphertext = make([]byte, n)
		}
	}

	d.Plaintext = nil // Forget any previous plaintext
	n, err = base64.StdEncoding.Decode(d.Ciphertext, text)
	d.Ciphertext = d.Ciphertext[:n]
	return err
}

// MarshalBinary returns DEK's ciphertext representation.
// It never returns an error.
func (d DEK) MarshalBinary() ([]byte, error) { return d.Ciphertext, nil }

// UnmarshalBinary sets DEK's ciphertext to the given data.
// It never returns an error and DEK's plaintext will be nil.
func (d *DEK) UnmarshalBinary(data []byte) error {
	n := len(data)
	if len(d.Ciphertext) < n {
		if cap(d.Ciphertext) >= n {
			d.Ciphertext = d.Ciphertext[:n]
		} else {
			d.Ciphertext = make([]byte, n)
		}
	}

	d.Plaintext = nil // Forget any previous plaintext
	copy(d.Ciphertext, data)
	return nil
}

// KeyInfo describes a cryptographic key at a KES server.
type KeyInfo struct {
	Name      string    // Name of the cryptographic key
	CreatedAt time.Time // Point in time when the key was created
	CreatedBy Identity  // Identity that created the key
}

// KeyIterator iterates over a stream of KeyInfo objects.
// Close the KeyIterator to release associated resources.
type KeyIterator struct {
	decoder *json.Decoder
	closer  io.Closer

	current KeyInfo
	err     error
	closed  bool
}

// Value returns the current KeyInfo. It returns
// the same KeyInfo until Next is called again.
//
// If KeyIterator has been closed or if Next has not been
// called once resp. once Next returns false then the
// behavior of Value is undefined.
func (i *KeyIterator) Value() KeyInfo { return i.current }

// Name returns the name of the current key. It is a
// short-hand for Value().Name.
func (i *KeyIterator) Name() string { return i.current.Name }

// CreatedAt returns the created-at timestamp of the current
// key. It is a short-hand for Value().CreatedAt.
func (i *KeyIterator) CreatedAt() time.Time { return i.current.CreatedAt }

// CreatedBy returns the identiy that created the current key.
// It is a short-hand for Value().CreatedBy.
func (i *KeyIterator) CreatedBy() Identity { return i.current.CreatedBy }

// Next returns true if there is another KeyInfo.
// It returns false if there are no more KeyInfo
// objects or when the KeyIterator encounters an
// error.
func (i *KeyIterator) Next() bool {
	type Response struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`

		Err string `json:"error"`
	}
	if i.closed || i.err != nil {
		return false
	}
	var resp Response
	if err := i.decoder.Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			i.err = i.Close()
		} else {
			i.err = err
		}
		return false
	}
	if resp.Err != "" {
		i.err = errors.New(resp.Err)
		return false
	}
	i.current = KeyInfo{
		Name:      resp.Name,
		CreatedAt: resp.CreatedAt,
		CreatedBy: resp.CreatedBy,
	}
	return true
}

// Close closes the IdentityIterator and releases
// any associated resources.
func (i *KeyIterator) Close() error {
	if !i.closed {
		err := i.closer.Close()
		if i.err == nil {
			i.err = err
		}
		i.closed = true
		return err
	}
	return i.err
}
