// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
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

// KeyIterator iterates over list of KeyDescription objects.
//   for iterator.Next() {
//       _ = iterator.Value() // Use the KeyDescription
//   }
//   if err := iterator.Err(); err != nil {
//   }
//   if err := iterator.Close(); err != nil {
//   }
//
// Once done with iterating over the list of KeyDescription
// objects, an iterator should be closed using the Close
// method.
//
// In general, a KeyIterator does not provide any guarantees
// about ordering or the when its underlying source is modified
// concurrently.
// Particularly, if a key is created or deleted at the KES server
// the KeyIterator may or may not be affected by this change.
type KeyIterator struct {
	response *http.Response
	decoder  *json.Decoder

	last     KeyDescription
	nextErr  error // error encountered in Next()
	closeErr error // error encountered in Close()
	closed   bool
}

// KeyDescription describes a cryptographic key at a KES server.
type KeyDescription struct {
	// Name is the name of the cryptographic key.
	Name string `json:"name"`
}

// Next returns true if there is another KeyDescription.
// This KeyDescription can be retrieved via the Value method.
//
// It returns false once there is no more KeyDescription
// or if the KeyIterator encountered an error. The error,
// if any, can be retrieved via the Err method.
func (i *KeyIterator) Next() bool {
	if i.closed || i.nextErr != nil {
		return false
	}
	if err := i.decoder.Decode(&i.last); err != nil {
		if err == io.EOF {
			i.nextErr = i.Close()
		} else {
			i.nextErr = err
		}
		return false
	}
	return true
}

// Value returns the current KeyDescription. It returns
// the same KeyDescription until Next is called again.
//
// If KeyIterator has been closed or if Next has not been
// called once resp. once Next returns false then the
// behavior of Value is undefined.
func (i *KeyIterator) Value() KeyDescription { return i.last }

// Err returns the first error encountered by the KeyIterator,
// if any.
func (i *KeyIterator) Err() error { return i.nextErr }

// Close closes the underlying connection to the KES server
// and returns any encountered error.
func (i *KeyIterator) Close() error {
	if !i.closed {
		i.closed = true
		if err := i.response.Body.Close(); err != nil {
			i.closeErr = err
		}
		if err := parseErrorTrailer(i.response.Trailer); err != nil && i.closeErr == nil {
			i.closeErr = err
		}
	}
	return i.closeErr
}
