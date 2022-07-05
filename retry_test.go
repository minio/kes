// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"io"
	"net"
	"net/url"
	"testing"
)

var retryBodyTests = []struct {
	Body io.ReadSeeker
}{
	{Body: nil},
	{Body: bytes.NewReader(nil)},
}

func TestRetryBody(t *testing.T) {
	for i, test := range retryBodyTests {
		body := retryBody(test.Body)
		if test.Body == nil && body != nil {
			t.Fatalf("Test %d: invalid retry body: got %v - want %v", i, body, test.Body)
		}
		if test.Body != nil {
			if _, ok := body.(io.Seeker); !ok {
				t.Fatalf("Test %d: retry body does not implement io.Seeker", i)
			}
		}
	}
}

var isNetworkErrorTests = []struct {
	Err            error
	IsNetworkError bool
}{
	{Err: nil, IsNetworkError: false},
	{Err: io.EOF, IsNetworkError: false},
	{Err: url.InvalidHostError(""), IsNetworkError: false},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: net.UnknownNetworkError("unknown"),
		},
		IsNetworkError: true,
	},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: &net.DNSError{},
		},
		IsNetworkError: true,
	},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: io.EOF,
		},
		IsNetworkError: true,
	},
}

func TestIsNetworkError(t *testing.T) {
	for i, test := range isNetworkErrorTests {
		temp := isNetworkError(test.Err)
		switch {
		case test.IsNetworkError == true && temp == false:
			t.Fatalf("Test %d: err should be a network error but it is not", i)
		case test.IsNetworkError == false && temp == true:
			t.Fatalf("Test %d: err should not be a network error but it is", i)
		}
	}
}
