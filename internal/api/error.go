// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"aead.dev/mem"
	"github.com/minio/kes/internal/headers"
)

// Failr responds to the client with err. The response
// status code is set to err.Status. The error encoding
// format is selected automatically based on the response
// content type. Handlers should return after calling Failr.
func Failr(r *Response, err Error) error {
	return Fail(r, err.Status(), err.Error())
}

// Failf responds to the client with the given status code
// and formatted error message. The message encoding format
// is selected automatically based on the response content
// type. Handlers should return after calling Failf.
func Failf(r *Response, code int, format string, a ...any) error {
	return Fail(r, code, fmt.Sprintf(format, a...))
}

// Fail responds to the client with the given status code
// and error message. The message encoding format is selected
// automatically based on the response content type. Handlers
// should return after calling Fail.
func Fail(r *Response, code int, msg string) error {
	var buf bytes.Buffer
	buf.WriteString(`{"message":`)
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		return err
	}
	buf.WriteByte('}')

	r.Header().Set(headers.ContentType, headers.ContentTypeJSON)
	r.Header().Set(headers.ContentLength, strconv.Itoa(buf.Len()))
	r.WriteHeader(code)
	_, err := r.Write(buf.Bytes())
	return err
}

// Error is an API error.
//
// Status codes should be within 400 (inclusive) and 600 (exclusive).
// HTTP clients treat status codes between 400 and 499 as client
// errors and status codes between 500 and 599 as server errors.
//
// Refer to the net/http package for a list of HTTP status codes.
type Error interface {
	error

	// Status returns the Error's HTTP status code.
	Status() int
}

// NewError returns a new Error from the given status code
// and error message.
func NewError(code int, msg string) Error {
	return &codeError{
		code: code,
		msg:  msg,
	}
}

// IsError reports whether any error in err's tree is an
// Error. It returns the first error that implements Error,
// if any.
//
// The tree consists of err itself, followed by the errors
// obtained by repeatedly unwrapping the error. When err
// wraps multiple errors, IsError examines err followed by
// a depth-first traversal of its children.
func IsError(err error) (Error, bool) {
	if err == nil {
		return nil, false
	}

	for {
		switch e := err.(type) {
		case Error:
			return e, true
		case interface{ Unwrap() error }:
			if err = e.Unwrap(); err == nil {
				return nil, false
			}
		case interface{ Unwrap() []error }:
			for _, err := range e.Unwrap() {
				if err, ok := IsError(err); ok {
					return err, true
				}
			}
			return nil, false
		default:
			return nil, false
		}
	}
}

// ReadError reads the response body into an Error using
// the response content encoding. It limits the response
// body to a reasonable size for typical error messages.
func ReadError(resp *http.Response) Error {
	const MaxSize = 5 * mem.KB // An error message should not exceed 5 KB.

	msg, err := readErrorMessage(resp, MaxSize)
	if err != nil {
		return NewError(resp.StatusCode, err.Error())
	}
	return NewError(resp.StatusCode, msg)
}

func readErrorMessage(resp *http.Response, maxSize mem.Size) (string, error) {
	size := mem.Size(resp.ContentLength)
	if size <= 0 || size > maxSize {
		size = maxSize
	}
	body := mem.LimitReader(resp.Body, size)

	switch resp.Header.Get(headers.ContentType) {
	case headers.ContentTypeHTML, headers.ContentTypeText:
		var sb strings.Builder
		if _, err := io.Copy(&sb, body); err != nil {
			return "", err
		}
		return sb.String(), nil
	default:
		type ErrResponse struct {
			Message string `json:"error"`
		}
		var response ErrResponse
		if err := json.NewDecoder(body).Decode(&response); err != nil {
			return "", err
		}
		return response.Message, nil
	}
}

type codeError struct {
	code int
	msg  string
}

func (e *codeError) Error() string { return e.msg }

func (e *codeError) Status() int { return e.code }
