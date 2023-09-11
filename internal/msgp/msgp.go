// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package msgp implements message pack encoding and decoding.
//
// Its generic Marshaler and Unmarshaler interface types decouple
// application types from their message pack representation.
// An arbitrary type T that implements Marshaler first gets converted
// to its message pack representation type R which then gets encoded
// to message pack data. Similarly, when unmarshaling message pack
// data it first gets decoded into R before converting R to T.
//
// All of this is done using static dispatch and without reflection
// using Go's generic type system and code generation for en/decoding
// binary data.
package msgp

import (
	"github.com/tinylib/msgp/msgp"
)

// Marshaler is implemented by types that return a type T
// containing their message pack representation. T's pointer
// type, *T, must implement the msgp.MarshalerSizer interface.
type Marshaler[T any, M interface {
	*T
	msgp.MarshalSizer
}] interface {
	MarshalMsg() (T, error)
}

// Unmarshaler is implemented by types that can unmarshal themself
// from a generic type T which can unmarshal itself from binary
// message pack data.
type Unmarshaler[T msgp.Unmarshaler] interface {
	UnmarshalMsg(T) error
}

// Marshal marshales a value of type T into binary message pack
// data. To do so, Marshal first converts v into its message
// package respresentation R and then encodes R into binary data.
func Marshal[R any, M interface {
	*R
	msgp.MarshalSizer
}, T Marshaler[R, M]](v T) ([]byte, error) {
	r, err := v.MarshalMsg()
	if err != nil {
		return nil, err
	}
	var m M = &r
	out := make([]byte, 0, m.Msgsize())
	return m.MarshalMsg(out)
}

// Unmarshal marshales binary message pack data into v. First, it
// decodes the binary data into T's message pack representation R.
// Then, it converts R to T.
func Unmarshal[R any, U interface {
	*R
	msgp.Unmarshaler
}, T Unmarshaler[U]](b []byte, v T) error {
	var r R
	var u U = &r
	if _, err := u.UnmarshalMsg(b); err != nil {
		return err
	}
	return v.UnmarshalMsg(u)
}
