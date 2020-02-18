// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"net/http"
	"testing"
)

var newErrorTests = []struct {
	Code    int
	Message string
	Err     Error
}{
	{Code: http.StatusBadRequest, Message: "", Err: NewError(http.StatusBadRequest, "")},
	{Code: http.StatusNotFound, Message: "key does not exist", Err: ErrKeyNotFound},
	{Code: http.StatusBadRequest, Message: "key does already exist", Err: ErrKeyExists},
	{Code: http.StatusForbidden, Message: "prohibited by policy", Err: ErrNotAllowed},
}

func TestNewError(t *testing.T) {
	for i, test := range newErrorTests {
		err := NewError(test.Code, test.Message)
		if err != test.Err {
			t.Fatalf("Test %d: got %v - want %v", i, err, test.Err)
		}
	}
}
