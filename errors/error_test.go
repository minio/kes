// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package errors

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
)

var hasStatusTests = []struct {
	Err       error
	HasStatus bool
}{
	{Err: New(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)), HasStatus: true},
	{Err: New(http.StatusInternalServerError, "some internal error"), HasStatus: true},
	{Err: errors.New("some internal error"), HasStatus: false},
	{Err: io.EOF, HasStatus: false},
}

func TestHasStatus(t *testing.T) {
	for i, test := range hasStatusTests {
		if hasStatus := HasStatus(test.Err); hasStatus != test.HasStatus {
			t.Errorf("Test %d: got %v - want %v", i, hasStatus, test.HasStatus)
		}
	}
}

var equalErrorTests = []struct {
	Err1, Err2 error
	Equal      bool
}{
	{
		Err1:  New(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)),
		Err2:  New(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)),
		Equal: true,
	},
	{
		Err1:  New(http.StatusInternalServerError, "some internal error"),
		Err2:  New(http.StatusInternalServerError, "some internal error"),
		Equal: true,
	},
	{
		Err1:  New(http.StatusInternalServerError, "some error"),
		Err2:  New(http.StatusInternalServerError, "some internal error"),
		Equal: false,
	},
	{
		Err1:  New(http.StatusBadRequest, "some error"),
		Err2:  New(http.StatusInternalServerError, "some error"),
		Equal: false,
	},
	{
		Err1:  New(http.StatusBadRequest, "some error"),
		Err2:  errors.New("some error"),
		Equal: false,
	},
}

func TestEqualError(t *testing.T) {
	for i, test := range equalErrorTests {
		if equal := test.Err1 == test.Err2; equal != test.Equal {
			t.Errorf("Test %d: got %v - want %v", i, equal, test.Equal)
		}
	}
}

var respondTests = []struct {
	Err    error
	Status int
	Body   string
}{
	{
		Err:    New(http.StatusBadRequest, "bad request"),
		Status: http.StatusBadRequest,
		Body:   `{"message":"bad request"}`,
	},
	{
		Err:    New(http.StatusInternalServerError, ""),
		Status: http.StatusInternalServerError,
		Body:   `{"message":""}`,
	},
	{
		Err:    nil,
		Status: http.StatusInternalServerError,
		Body:   `{}`,
	},
	{
		Err:    io.EOF,
		Status: http.StatusInternalServerError,
		Body:   `{"message":"EOF"}`,
	},
}

func TestRespond(t *testing.T) {
	for i, test := range respondTests {
		var w responseWriter
		Respond(&w, test.Err)

		if contentType := w.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
			t.Fatalf("Test %d: got content-type: %s - want content-type prefix: %s", i, contentType, "application/json")
		}
		if noSniff := w.Header().Get("X-Content-Type-Options"); noSniff != "nosniff" {
			t.Fatalf("Test %d: got: %s - want: %s", i, noSniff, "nosniff")
		}

		if w.Status != test.Status {
			t.Fatalf("Test %d: got status %d - want status %d", i, w.Status, test.Status)
		}
		if body := w.Body.String(); body != test.Body {
			t.Fatalf("Test %d: got body: %s - want body: %s", i, body, test.Body)
		}
	}
}

var parseResponseTests = []struct {
	ServerErr error
	ClientErr error
}{
	{
		ServerErr: New(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)),
		ClientErr: New(http.StatusBadRequest, http.StatusText(http.StatusBadRequest)),
	},
	{
		ServerErr: nil,
		ClientErr: New(http.StatusInternalServerError, ""),
	},
	{
		ServerErr: io.EOF,
		ClientErr: New(http.StatusInternalServerError, "EOF"),
	},
	{
		ServerErr: New(http.StatusNotFound, "key does not exist"),
		ClientErr: New(http.StatusNotFound, "key does not exist"),
	},
}

func TestParseResponse(t *testing.T) {
	for i, test := range parseResponseTests {
		var w responseWriter
		Respond(&w, test.ServerErr)

		resp := &http.Response{
			StatusCode:    w.Status,
			Status:        http.StatusText(w.Status),
			Header:        w.Header().Clone(),
			ContentLength: int64(w.Body.Len()),
			Body:          ioutil.NopCloser(&w.Body),
		}
		err := ParseResponse(resp)
		if err != test.ClientErr {
			t.Fatalf("Test %d: got %v - want %v", i, err, test.ClientErr)
		}
	}
}

var _ http.ResponseWriter = (*responseWriter)(nil)
var _ http.Flusher = (*responseWriter)(nil)

type responseWriter struct {
	Status int
	Body   bytes.Buffer

	header     http.Header
	hasWritten bool
}

func (r *responseWriter) Flush() {}

func (r *responseWriter) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if !r.hasWritten {
		r.hasWritten = true
		r.Status = statusCode
	}
}

func (r *responseWriter) Write(b []byte) (int, error) {
	if !r.hasWritten {
		r.hasWritten = true
		r.Status = http.StatusOK
	}
	return r.Body.Write(b)
}
