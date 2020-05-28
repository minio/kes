// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"net/http"
	"testing"
)

var validatePathHandlerTests = []struct {
	Pattern     string
	Path        string
	ShouldMatch bool
}{
	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/my-key", ShouldMatch: true},                      // 0
	{Pattern: "/v1/key/import/*", Path: "/v1/key/import/my-key", ShouldMatch: true},                      // 1
	{Pattern: "/v1/key/delete/*", Path: "/v1/key/delete/my-key", ShouldMatch: true},                      // 2
	{Pattern: "/v1/key/generate/*", Path: "/v1/key/generate/my-key", ShouldMatch: true},                  // 3
	{Pattern: "/v1/key/encrypt/*", Path: "/v1/key/encrypt/my-key", ShouldMatch: true},                    // 4
	{Pattern: "/v1/key/decrypt/*", Path: "/v1/key/decrypt/my-key", ShouldMatch: true},                    // 5
	{Pattern: "/v1/policy/write/*", Path: "/v1/policy/write/my-policy", ShouldMatch: true},               // 6
	{Pattern: "/v1/policy/read/*", Path: "/v1/policy/read/my-policy", ShouldMatch: true},                 // 7
	{Pattern: "/v1/policy/list/*", Path: "/v1/policy/list/my-policy", ShouldMatch: true},                 // 8
	{Pattern: "/v1/policy/list/*", Path: "/v1/policy/list/*", ShouldMatch: true},                         // 9
	{Pattern: "/v1/policy/delete/*", Path: "/v1/policy/delete/my-policy", ShouldMatch: true},             // 10
	{Pattern: "/v1/identity/assign/*/*", Path: "/v1/identity/assign/af43c/my-policy", ShouldMatch: true}, // 11
	{Pattern: "/v1/identity/list/*", Path: "/v1/identity/list/af43c", ShouldMatch: true},                 // 12
	{Pattern: "/v1/identity/list/*", Path: "/v1/identity/list/*", ShouldMatch: true},                     // 13
	{Pattern: "/v1/identity/forget/*", Path: "/v1/identity/forget/af43c", ShouldMatch: true},             // 14

	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/my-key/..", ShouldMatch: false},   // 15
	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/../my-key", ShouldMatch: false},   // 16
	{Pattern: "/v1/key/decypt/*", Path: "/v1/key/create/my-key", ShouldMatch: false},      // 17
	{Pattern: "/v1/key/generate/*", Path: "/v1/key/create/my-key/x", ShouldMatch: false},  // 18
	{Pattern: "/v1/key/create/[a-z]", Path: "/v1/key/create/my-key0", ShouldMatch: false}, // 19
	{Pattern: "/v1/key/decypt/*", Path: "/v1/key/create/./*/../a", ShouldMatch: false},    // 20
}

func TestValidatePathHandler(t *testing.T) {
	const baseURL = "https://localhost:7373"
	var f = func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusOK) }

	for i, test := range validatePathHandlerTests {
		req, err := http.NewRequest(http.MethodGet, baseURL+test.Path, nil)
		if err != nil {
			t.Fatalf("Test %d: failed to create request URL: %v", i, err)
		}

		var resp dummyResponseWriter
		ValidatePath(test.Pattern, f)(&resp, req)
		if test.ShouldMatch && resp.StatusCode != http.StatusOK {
			t.Fatalf("Test %d: path should have matched pattern: got %d - want %d", i, resp.StatusCode, http.StatusOK)
		}
		if !test.ShouldMatch && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Test %d: path should not have matched pattern: got %d - want %d", i, resp.StatusCode, http.StatusBadRequest)
		}
	}
}

var (
	_ http.ResponseWriter = (*dummyResponseWriter)(nil)
	_ http.Flusher        = (*dummyResponseWriter)(nil)
)

// dummyResponseWriter is a helper type to test
// HTTP handler functions.
type dummyResponseWriter struct {
	Headers    http.Header
	StatusCode int
	Body       bytes.Buffer

	written bool
}

func (d *dummyResponseWriter) Header() http.Header {
	if d.Headers == nil {
		d.Headers = make(http.Header)
	}
	return d.Headers
}

func (d *dummyResponseWriter) WriteHeader(statusCode int) {
	if !d.written {
		d.StatusCode = statusCode
		d.written = true
	}
}

func (d *dummyResponseWriter) Write(p []byte) (int, error) {
	if !d.written {
		d.WriteHeader(http.StatusOK)
	}
	return d.Body.Write(p)
}
func (d *dummyResponseWriter) Flush() {}
