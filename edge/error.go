// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"errors"
	"net"
)

// Unreachable is an error that indicates that the
// key store is not reachable - for example due to a
// a network error.
type Unreachable struct {
	Err error
}

// IsUnreachable reports whether err is an Unreachable
// error. If IsUnreachable returns true it returns err
// as Unreachable error.
func IsUnreachable(err error) (*Unreachable, bool) {
	var u *Unreachable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}

func (e *Unreachable) Error() string {
	if e.Err == nil {
		return "keystore: not reachable"
	}
	return "keystore: not reachable: " + e.Err.Error()
}

// Unwrap returns the Unreachable's underlying error,
// if any.
func (e *Unreachable) Unwrap() error { return e.Err }

// Timeout reports whether the Unreachable error
// is caused by a network timeout.
func (e *Unreachable) Timeout() bool {
	var err net.Error
	if errors.As(e.Err, &err) {
		return err.Timeout()
	}
	return false
}

// Unavailable is an error that indicates that the
// key store is reachable over the network but not ready
// to process requests - e.g. the Store might not be
// initialized.
type Unavailable struct {
	Err error
}

// IsUnavailable reports whether err is an Unavailable
// error. If IsUnavailable returns true it returns err
// as Unavailable error.
func IsUnavailable(err error) (*Unavailable, bool) {
	var u *Unavailable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}

func (e *Unavailable) Error() string {
	if e.Err == nil {
		return "keystore: not available"
	}
	return "keystore: not available: " + e.Err.Error()
}

// Unwrap returns the Unavailable's underlying error,
// if any.
func (e *Unavailable) Unwrap() error { return e.Err }
