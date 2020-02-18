// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import "net/http"

var (
	ErrKeyNotFound Error = NewError(http.StatusNotFound, "key does not exist")
	ErrKeyExists   Error = NewError(http.StatusBadRequest, "key does already exist")
	ErrNotAllowed  Error = NewError(http.StatusForbidden, "prohibited by policy")
)

// Error is the type of client-server API errors.
// A Client returns an Error if a server responds
// with a well-formed error message.
//
// An Error contains the HTTP status code sent by
// the server. Errors with the same status code and
// error message are equal. In particular:
//   ErrKeyExists == NewError(400, "key does already exist") // true
//
// The client may distinguish errors as following:
//   switch err := client.CreateKey("example-key"); err {
//       case nil: // Success!
//       case ErrKeyExists:
//          // The key "example-key" already exists.
//       case ErrNotAllowed:
//          // We don't have the permission to create this key.
//       default:
//          // Something else when wrong.
//   }
type Error struct {
	code    int
	message string
}

// NewError returns a new Error with the given
// HTTP status code and error message.
//
// Two errors with the same status code and
// error message are equal.
func NewError(code int, msg string) Error {
	return Error{
		code:    code,
		message: msg,
	}
}

// Status returns the HTTP status code of the error.
func (e Error) Status() int { return e.code }

func (e Error) Error() string { return e.message }
