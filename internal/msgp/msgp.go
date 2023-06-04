// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import (
	"github.com/tinylib/msgp/msgp"
)

type Marshaler[T any] interface {
	MarshalMsg() (T, error)
}

type Unmarshaler[T any] interface {
	UnmarshalMsg(T) error
}

func Marshal[M any, C interface {
	msgp.MarshalSizer
	*M
}, T Marshaler[M]](v T,
) ([]byte, error) {
	m, err := v.MarshalMsg()
	if err != nil {
		return nil, err
	}
	var c C = &m
	out := make([]byte, 0, c.Msgsize())
	return c.MarshalMsg(out)
}

func Unmarshal[M any, C interface {
	msgp.Unmarshaler
	*M
}, T Unmarshaler[C]](b []byte, v T,
) error {
	var m M
	var c C = &m
	if _, err := c.UnmarshalMsg(b); err != nil {
		return err
	}
	return v.UnmarshalMsg(c)
}
