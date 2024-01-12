// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package protobuf

import (
	"time"

	"google.golang.org/protobuf/proto"
	pbt "google.golang.org/protobuf/types/known/timestamppb"
)

// Marshaler is an interface implemented by types that
// know how to marshal themselves into their protobuf
// representation T.
type Marshaler[T proto.Message] interface {
	MarshalPB(T) error
}

// Unmarshaler is an interface implemented by types that
// know how to unmarshal themselves from their protobuf
// representation T.
type Unmarshaler[T proto.Message] interface {
	UnmarshalPB(T) error
}

// Marshal returns v's protobuf binary data by first converting
// v into its protobuf representation type M and then marshaling
// M into the protobuf wire format.
func Marshal[M any, P Pointer[M], T Marshaler[P]](v T) ([]byte, error) {
	var m M
	if err := v.MarshalPB(&m); err != nil {
		return nil, err
	}

	var p P = &m
	return proto.Marshal(p)
}

// Unmarshal unmarshales v from b by first decoding b into v's
// protobuf representation M before converting M to v. It returns
// an error if b is not a valid protobuf representation of v.
func Unmarshal[M any, P Pointer[M], T Unmarshaler[P]](b []byte, v T) error {
	var m M
	var p P = &m
	if err := proto.Unmarshal(b, p); err != nil {
		return err
	}
	return v.UnmarshalPB(p)
}

// Time returns a new protobuf timestamp from the given t.
func Time(t time.Time) *pbt.Timestamp { return pbt.New(t) }

// Pointer is a type constraint used to express that some
// type P is a pointer of some other type T such that:
//
//	var t T
//	var p P = &t
//
// This proposition is useful when unmarshaling data into types
// without additional dynamic dispatch or heap allocations.
//
// A generic function that wants to use the default value of
// some type T but also wants to call pointer receiver methods
// on instances of T has to have two type parameters:
//
//	func foo[T any, P pointer[T]]() {
//	    var t T
//	    var p P = &t
//	}
//
// This functionality cannot be achieved with a single type
// parameter because:
//
//	func foo[T proto.Message]() {
//	    var t T             // compiles but t is nil if T is a pointer type
//	    var t2 T = *new(T)  // compiles but t2 is nil if T is a pointer type
//	    var t3 = T{}        // compiler error - e.g. T may be a pointer type
//	}
type Pointer[M any] interface {
	proto.Message
	*M // Anything implementing Pointer must also be a pointer type of M
}
