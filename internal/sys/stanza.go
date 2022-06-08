// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"encoding"
	"encoding/gob"
)

// A Stanza describes a sealed value.
type Stanza struct {
	// Type describes the seal/unseal method used to
	// produce this Stanza.
	Type string

	// Body contains the sealed information. It's
	// an opaque byte string specific to the seal
	// method.
	Body []byte
}

var (
	_ encoding.BinaryMarshaler   = Stanza{}
	_ encoding.BinaryUnmarshaler = (*Stanza)(nil)
)

// MarshalBinary returns the Stanza's binary representation.
func (s Stanza) MarshalBinary() ([]byte, error) {
	type GOB struct {
		Type string
		Body []byte
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(GOB(s)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalBinary unmarshals the Stanza's binary representation.
func (s *Stanza) UnmarshalBinary(b []byte) error {
	type GOB struct {
		Type string
		Body []byte
	}

	var value GOB
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&value); err != nil {
		return err
	}
	s.Type = value.Type
	s.Body = value.Body
	return nil
}
