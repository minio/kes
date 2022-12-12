// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
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

// All valid cryptographic algorithms that can be used with keys.
const (
	KeyAlgorithmUndefined KeyAlgorithm = iota
	AES256_GCM_SHA256
	XCHACHA20_POLY1305
)

// KeyAlgorithm is an enum representing the algorithm
// a cryptographic key can be used with.
type KeyAlgorithm uint

// String returns the KeyAlgorithm's string representation.
func (a KeyAlgorithm) String() string {
	switch a {
	case KeyAlgorithmUndefined:
		return "undefined"
	case AES256_GCM_SHA256:
		return "AES256-GCM_SHA256"
	case XCHACHA20_POLY1305:
		return "XCHACHA20-POLY1305"
	default:
		return "invalid algorithm '" + strconv.Itoa(int(a)) + "'"
	}
}

// MarshalText returns the KeyAlgorithm's text representation.
// In contrast to String, it represents KeyAlgorithmUndefined
// as empty string and returns an error if the KeyAlgorithm
// isn't valid.
func (a KeyAlgorithm) MarshalText() ([]byte, error) {
	switch a {
	case KeyAlgorithmUndefined:
		return []byte{}, nil
	case AES256_GCM_SHA256:
		return []byte("AES256-GCM_SHA256"), nil
	case XCHACHA20_POLY1305:
		return []byte("XCHACHA20-POLY1305"), nil
	default:
		return nil, errors.New("key: invalid algorithm '" + strconv.Itoa(int(a)) + "'")
	}
}

// UnmarshalText parses text as KeyAlgorithm text representation.
func (a *KeyAlgorithm) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*a = KeyAlgorithmUndefined
		return nil
	}

	switch s := string(text); s {
	case "undefined":
		*a = KeyAlgorithmUndefined
		return nil
	case "AES256-GCM_SHA256":
		*a = AES256_GCM_SHA256
		return nil
	case "XCHACHA20-POLY1305":
		*a = XCHACHA20_POLY1305
		return nil
	default:
		return errors.New("key: invalid algorithm '" + s + "'")
	}
}

// KeyInfo describes a cryptographic key at a KES server.
type KeyInfo struct {
	Name      string       // Name of the cryptographic key
	ID        string       // ID of the cryptographic key
	Algorithm KeyAlgorithm // Cryptographic algorithm the key can be used with
	CreatedAt time.Time    // Point in time when the key was created
	CreatedBy Identity     // Identity that created the key
}

// MarshalJSON returns the KeyInfo's JSON representation.
func (k *KeyInfo) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Name      string       `json:"name"`
		ID        string       `json:"id,omitempty"`
		Algorithm KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy Identity     `json:"created_by,omitempty"`
	}
	return json.Marshal(JSON{
		Name:      k.Name,
		ID:        k.ID,
		Algorithm: k.Algorithm,
		CreatedAt: k.CreatedAt,
		CreatedBy: k.CreatedBy,
	})
}

// UnmarshalJSON parses text as KeyInfo JSON representation.
func (k *KeyInfo) UnmarshalJSON(text []byte) error {
	type JSON struct {
		Name      string       `json:"name"`
		ID        string       `json:"id"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy Identity     `json:"created_by"`
	}
	var v JSON
	if err := json.Unmarshal(text, &v); err != nil {
		return err
	}

	k.Name = v.Name
	k.ID = v.ID
	k.Algorithm = v.Algorithm
	k.CreatedAt = v.CreatedAt
	k.CreatedBy = v.CreatedBy
	return nil
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

// ID returns the ID of the current key. It is a
// short-hand for Value().ID.
func (i *KeyIterator) ID() string { return i.current.ID }

// Algorithm returns the KeyAlgorithm of the current key. It is a
// short-hand for Value().Algorithm.
func (i *KeyIterator) Algorithm() KeyAlgorithm { return i.current.Algorithm }

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
		Name      string       `json:"name"`
		ID        string       `json:"id"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy Identity     `json:"created_by"`

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
		ID:        resp.ID,
		Algorithm: resp.Algorithm,
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
		Name      string       `json:"name"`
		ID        string       `json:"id"`
		Algorithm KeyAlgorithm `json:"algorithm"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy Identity     `json:"created_by"`

		Err string `json:"error"`
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
		info := KeyInfo{
			Name:      resp.Name,
			ID:        resp.ID,
			Algorithm: resp.Algorithm,
			CreatedAt: resp.CreatedAt,
			CreatedBy: resp.CreatedBy,
		}
		if err := encoder.Encode(info); err != nil {
			i.err = err
			return cw.N, err
		}
	}
}

// Values returns up to the next n KeyInfo values. Subsequent
// calls will yield further PolicyInfos if there are any.
//
// If n > 0, Values returns at most n KeyInfo structs. In this case,
// if Values returns an empty slice, it will return an error explaining
// why. At the end of the listing, the error is io.EOF.
//
// If n <= 0, Values returns all remaining KeyInfo records. In this
// case, Values always closes the KeyIterator. When it succeeds, it
// returns a nil error, not io.EOF.
func (i *KeyIterator) Values(n int) ([]KeyInfo, error) {
	values := []KeyInfo{}
	if n > 0 && i.closed {
		return values, io.EOF // Return early, don't alloc a slice
	}
	if n > 0 {
		values = make([]KeyInfo, 0, n)
	}

	var count int
	for i.Next() {
		values = append(values, i.Value())
		count++

		if n > 0 && count >= n {
			return values, nil
		}
	}
	if err := i.Close(); err != nil {
		return values, err
	}
	if n > 0 && len(values) == 0 { // As by doc contract
		return values, io.EOF
	}
	return values, nil
}

// Close closes the KeyIterator and releases
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
