// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package key

import (
	"errors"
	"strconv"
)

const (
	v1 version = 1
)

// version is an enum representing the format version
// of text/binary encoded keys.
type version uint

// String returns the version's string representation.
func (v version) String() string {
	switch v {
	case v1:
		return "v1"
	default:
		return "invalid version '" + strconv.Itoa(int(v)) + "'"
	}
}

// String returns the version's text representation.
// In contrast to String, it returns an error for invalid
// versions.
func (v version) MarshalText() ([]byte, error) {
	switch v {
	case v1:
		return []byte("v1"), nil
	default:
		return nil, errors.New("key: invalid version '" + strconv.Itoa(int(v)) + "'")
	}
}

// UnmarshalText parses text as version text representation.
func (v *version) UnmarshalText(text []byte) error {
	switch s := string(text); s {
	case "v1":
		*v = v1
		return nil
	default:
		return errors.New("key: invalid version '" + s + "'")
	}
}
