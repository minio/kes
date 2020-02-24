// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"fmt"
	"io"
	"net/http"
)

// Error sends the given err as JSON error responds to w.
//
// If err has a 'Status() int' method then Error sets the
// response status code to err.Status(). Otherwise, it will
// send 500 (internal server error).
//
// If err is nil then Error will send the status code 500 and
// an empty JSON response body - i.e. '{}'.
func Error(w http.ResponseWriter, err error) error {
	var status = http.StatusInternalServerError
	if e, ok := err.(interface{ Status() int }); ok {
		status = e.Status()
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
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
