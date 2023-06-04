// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
	var (
		code = http.StatusInternalServerError
		stat interface {
			error
			Status() int
		}
	)
	if errors.As(err, &stat) {
		code = stat.Status()
		err = stat
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
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
