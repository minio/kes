// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package kes

// NewError returns an error that formats as the given text.
//
// It's guaranteed that the returned error has an additional
//    Status() int
// method that returns the given status code. Code that handles
// HTTP requests may type-check whether an error value provides
// this method by:
//    if err, ok := err.(interface{ Status() int }); ok {
//    }
// and set the status code of the response accordingly.
//
// NewError should not be used to create internal errors,
// like when running out-of-entropy while reading from a PRNG.
//
// Each call to NewError returns a distinct error value even
// if the status and text are identical.
func NewError(status int, text string) error {
	return &httpError{
		status: status,
		text:   text,
	}
}

type httpError struct {
	status int
	text   string
}

func (e *httpError) Status() int { return e.status }

func (e *httpError) Error() string { return e.text }
