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

var isTemporaryTests = []struct {
	Err         error
	IsTemporary bool
}{
	{Err: nil, IsTemporary: false},
	{Err: io.EOF, IsTemporary: false},
	{Err: url.InvalidHostError(""), IsTemporary: false},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: net.UnknownNetworkError("unknown"),
		},
		IsTemporary: false,
	},
	{
		Err: &url.Error{
			Op:  "GET",
			URL: "http://127.0.0.1",
			Err: io.EOF,
		},
		IsTemporary: true,
	},
}

func TestIsTemporary(t *testing.T) {
	for i, test := range isTemporaryTests {
		temp := isTemporary(test.Err)
		switch {
		case test.IsTemporary == true && temp == false:
			t.Fatalf("Test %d: err should be temporary but it is not", i)
		case test.IsTemporary == false && temp == true:
			t.Fatalf("Test %d: err should not be temporary but it is", i)
		}
	}
}
