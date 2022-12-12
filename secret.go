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

// SecretOptions is a struct containing customization
// options for secret - like the Secret type.
type SecretOptions struct {
	// Type specifies the type of the Secret.
	// Its default vaule is SecretGeneric.
	Type SecretType
}

// All valid secret types.
const (
	SecretGeneric SecretType = iota
)

// SecretType is an enum representing the type of a Secret.
type SecretType uint

// String returns the SecretType string representation.
func (s SecretType) String() string {
	switch s {
	case SecretGeneric:
		return "generic"
	default:
		return "%" + strconv.Itoa(int(s))
	}
}

// MarshalText returns the SecretType text representation.
// In contrast to String, it returns an error if s is not
// a valid SecretType.
func (s SecretType) MarshalText() ([]byte, error) {
	switch s {
	case SecretGeneric:
		return []byte("generic"), nil
	default:
		return nil, errors.New("kes: invalid secret type '%" + strconv.Itoa(int(s)) + "'")
	}
}

// UnmarshalText decodes the given SecretType text
// representation into s. It returns an error if
// text is not a valid SecretType.
func (s *SecretType) UnmarshalText(text []byte) error {
	switch v := string(text); v {
	case "generic":
		*s = SecretGeneric
		return nil
	default:
		return errors.New("kes: invalid secret type '" + v + "'")
	}
}

// SecretInfo describes a secret at a KES server.
type SecretInfo struct {
	Name      string     // The name of the secret
	Type      SecretType // The type of secret
	CreatedAt time.Time  // Point in time when the secret was created
	ModTime   time.Time  // Most recent point in time when the secret has been modified.
	CreatedBy Identity   // Identity that created the secret
}

// MarshalJSON returns the SecretInfo JSON representation.
func (s *SecretInfo) MarshalJSON() ([]byte, error) {
	type JSON struct {
		Name      string     `json:"name,omitempty"`
		Type      SecretType `json:"type,omitempty"`
		CreatedAt time.Time  `json:"created_at,omitempty"`
		ModTime   time.Time  `json:"mod_time,omitempty"`
		CreatedBy Identity   `json:"created_by,omitempty"`
	}
	modTime := s.ModTime
	if modTime.IsZero() {
		modTime = s.CreatedAt
	}
	return json.Marshal(JSON{
		Name:      s.Name,
		Type:      s.Type,
		CreatedAt: s.CreatedAt,
		ModTime:   modTime,
		CreatedBy: s.CreatedBy,
	})
}

// UnmarshalJSON decodes the given JSON data into the SecretInfo.
func (s *SecretInfo) UnmarshalJSON(data []byte) error {
	type JSON struct {
		Name      string     `json:"name"`
		Type      SecretType `json:"type"`
		CreatedAt time.Time  `json:"created_at"`
		ModTime   time.Time  `json:"mod_time"`
		CreatedBy Identity   `json:"created_by"`
	}

	var v JSON
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	s.Name = v.Name
	s.Type = v.Type
	s.CreatedAt = v.CreatedAt
	s.ModTime = v.ModTime
	s.CreatedBy = v.CreatedBy

	if s.ModTime.IsZero() {
		s.ModTime = v.CreatedAt
	}
	return nil
}

// SecretIter iterates over a stream of SecretInfo objects.
// Close the SecretIter to release associated resources.
type SecretIter struct {
	decoder *json.Decoder
	closer  io.Closer

	current SecretInfo
	err     error
	closed  bool
}

// Value returns the current SecretInfo. It returns
// the same SecretInfo until Next is called again.
//
// If SecretIter has been closed or if Next has not been
// called once resp. once Next returns false then the
// behavior of Value is undefined.
func (i *SecretIter) Value() SecretInfo { return i.current }

// Name returns the name of the current secret. It is a
// short-hand for Value().Name.
func (i *SecretIter) Name() string { return i.current.Name }

// Type returns the type of the current secret. It is a
// short-hand for Value().Type.
func (i *SecretIter) Type() SecretType { return i.current.Type }

// CreatedAt returns the created-at timestamp of the current
// secret. It is a short-hand for Value().CreatedAt.
func (i *SecretIter) CreatedAt() time.Time { return i.current.CreatedAt }

// ModTime returns the most recent point in time at which the
// secret has been modified. If the secret has never been modified
// ModTime is equal to CreatedAt.
//
// It is a short-hand for Value().ModTime.
func (i *SecretIter) ModTime() time.Time { return i.current.ModTime }

// CreatedBy returns the identiy that created the current
// secret. It is a short-hand for Value().CreatedBy.
func (i *SecretIter) CreatedBy() Identity { return i.current.CreatedBy }

// Next returns true if there is another SecretInfo.
// It returns false if there are no more SecretInfo
// objects or when the SecretIter encounters an
// error.
func (i *SecretIter) Next() bool {
	type Response struct {
		Name      string    `json:"name"`
		Type      int       `json:"type"`
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
	i.current = SecretInfo{
		Name:      resp.Name,
		CreatedAt: resp.CreatedAt,
		CreatedBy: resp.CreatedBy,
	}
	return true
}

// WriteTo encodes and writes all remaining SecretInfos
// from its current iterator position to w. It returns
// the number of bytes written to w and the first error
// encounterred, if any.
func (i *SecretIter) WriteTo(w io.Writer) (int64, error) {
	type Response struct {
		Name      string    `json:"name,omitempty"`
		Type      int       `json:"type,omitempty"`
		CreatedAt time.Time `json:"created_at,omitempty"`
		ModTime   time.Time `json:"mod_time,omitempty"`
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
		if resp.ModTime.IsZero() {
			resp.ModTime = resp.CreatedAt
		}
		if err := encoder.Encode(resp); err != nil {
			i.err = err
			return cw.N, err
		}
	}
}

// Values returns up to the next n SecretInfo values. Subsequent
// calls will yield further SecretInfos if there are any.
//
// If n > 0, Values returns at most n SecretInfo structs. In this case,
// if Values returns an empty slice, it will return an error explaining
// why. At the end of the listing, the error is io.EOF.
//
// If n <= 0, Values returns all remaining SecretInfo records. In this
// case, Values always closes the SecretIter. When it succeeds, it
// returns a nil error, not io.EOF.
func (i *SecretIter) Values(n int) ([]SecretInfo, error) {
	values := []SecretInfo{}
	if n > 0 && i.closed {
		return values, io.EOF // Return early, don't alloc a slice
	}
	if n > 0 {
		values = make([]SecretInfo, 0, n)
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

// Close closes the SecretIter and releases any associated resources.
func (i *SecretIter) Close() error {
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
