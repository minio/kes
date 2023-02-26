// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"fmt"
	"io"
	"net/http"
)

// StatusCode is an interface implemented by types
// that want to send a custom HTTP status code to
// clients.
type StatusCode interface {
	// Status returns an HTTP status code.
	Status() int
}

// Fail sends an error response to the w.
//
// If error implements the StatusCode interface, Fail
// sends the response with the returned status code.
// Otherwise, Fail sends a HTTP 500 status code
// (internal server error).
//
// If err is nil, Fail sends the HTTP 500 status code
// and an empty response body.
//
// Fail returns an error if writing to w fails.
func Fail(w http.ResponseWriter, err error) error {
	status := http.StatusInternalServerError
	if s, ok := err.(StatusCode); ok {
		status = s.Status()
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if e, ok := err.(interface{ Header() http.Header }); ok {
		for k, values := range e.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
	}
	w.WriteHeader(status)

	const (
		emptyMsg = `{}`
		format   = `{"message":"%v"}`
	)
	if err == nil {
		_, err = io.WriteString(w, emptyMsg)
	} else {
		_, err = io.WriteString(w, fmt.Sprintf(format, err))
	}
	return err
}
