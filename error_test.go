// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
)

var newErrorTests = []struct {
	Code    int
	Message string
	Err     Error
}{
	{Code: http.StatusBadRequest, Message: "", Err: NewError(http.StatusBadRequest, "")},
	{Code: http.StatusNotFound, Message: "key does not exist", Err: ErrKeyNotFound},
	{Code: http.StatusBadRequest, Message: "key already exists", Err: ErrKeyExists},
	{Code: http.StatusForbidden, Message: "not authorized: insufficient permissions", Err: ErrNotAllowed},
}

func TestNewError(t *testing.T) {
	for i, test := range newErrorTests {
		err := NewError(test.Code, test.Message)
		if err != test.Err {
			t.Fatalf("Test %d: got %v - want %v", i, err, test.Err)
		}
	}
}

var isConnErrorTests = []struct {
	Err         error
	IsConnError bool
}{
	{Err: &ConnError{}, IsConnError: true},                                  // 0
	{Err: fmt.Errorf("wrapped error: %w", &ConnError{}), IsConnError: true}, // 1
	{Err: &url.Error{Err: &ConnError{}}, IsConnError: true},                 // 2

	{Err: fmt.Errorf("wrapped error: %w", &url.Error{}), IsConnError: false}, // 3
	{Err: io.EOF, IsConnError: false},                                        // 4
}

func TestIsConnError(t *testing.T) {
	for i, test := range isConnErrorTests {
		_, ok := IsConnError(test.Err)
		if test.IsConnError && !ok {
			t.Fatalf("Test %d: error '%s' is a ConnError", i, test.Err)
		}
		if !test.IsConnError && ok {
			t.Fatalf("Test %d: error '%s' is not a ConnError", i, test.Err)
		}
	}
}
