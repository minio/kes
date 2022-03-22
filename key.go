// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
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
type DEK struct {
	Plaintext  []byte
	Ciphertext []byte
}

// CCP is a structure wrapping a ciphertext / decryption context
// pair.
//
// Its main purpose is to group a ciphertext and decryption
// context to improve API ergonomics.
type CCP struct {
	Ciphertext []byte // Ciphertext bytes
	Context    []byte // Decryption context
}

// PCP is a structure wrapping a plaintext / encryption context
// pair.
//
// Its main purpose is to group a plaintext and encryption
// context to improve API ergonomics.
type PCP struct {
	Plaintext []byte
	Context   []byte
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

// WriteTo encodes and writes all remaining KeyInfos
// from its current iterator position to w. It returns
// the number of bytes written to w and the first error
// encounterred, if any.
func (i *KeyIterator) WriteTo(w io.Writer) (int64, error) {
	type Response struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at,omitempty"`
		CreatedBy Identity  `json:"created_by,omitempty"`

		Err string `json:"error,omitempty"`
	}
	if i.err != nil {
		return 0, i.err
	}
	if i.closed {
		return 0, errors.New("kes: WriteTo called after Close")
	}

	cw := countWriter{W: w}
	encoder := json.NewEncoder(&cw)
	for {
		var resp Response
		if err := i.decoder.Decode(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				i.err = i.Close()
			} else {
				i.err = err
			}
			return cw.N, i.err
		}
		if resp.Err != "" {
			i.err = errors.New(resp.Err)
			return cw.N, i.err
		}
		if err := encoder.Encode(resp); err != nil {
			i.err = err
			return cw.N, err
		}
	}
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
