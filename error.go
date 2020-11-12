// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	// ErrNotAllowed represents a KES server response returned when the
	// client has not sufficient policy permissions to perform a particular
	// operation.
	ErrNotAllowed Error = NewError(http.StatusForbidden, "prohibited by policy")

	// ErrKeyNotFound represents a KES server response returned when a client
	// tries to access or use a cryptographic key which does not exist.
	ErrKeyNotFound Error = NewError(http.StatusNotFound, "key does not exist")

	// ErrKeyExists represents a KES server response returned when a client tries
	// to create a cryptographic key which already exists.
	ErrKeyExists Error = NewError(http.StatusBadRequest, "key does already exist")

	// ErrPolicyNotFound represents a KES server response returned when a client
	// tries to access a policy which does not exist.
	ErrPolicyNotFound Error = NewError(http.StatusNotFound, "policy does not exist")
)

// Error is the type of client-server API errors.
// A Client returns an Error if a server responds
// with a well-formed error message.
//
// An Error contains the HTTP status code sent by
// the server. Errors with the same status code and
// error message are equal. In particular:
//   ErrKeyExists == NewError(400, "key does already exist") // true
//
// The client may distinguish errors as following:
//   switch err := client.CreateKey("example-key"); err {
//       case nil: // Success!
//       case ErrKeyExists:
//          // The key "example-key" already exists.
//       case ErrNotAllowed:
//          // We don't have the permission to create this key.
//       default:
//          // Something else went wrong.
//   }
type Error struct {
	code    int
	message string
}

// NewError returns a new Error with the given
// HTTP status code and error message.
//
// Two errors with the same status code and
// error message are equal.
func NewError(code int, msg string) Error {
	return Error{
		code:    code,
		message: msg,
	}
}

// Status returns the HTTP status code of the error.
func (e Error) Status() int { return e.code }

func (e Error) Error() string { return e.message }

// parseErrorResponse returns an error containing
// the response status code and response body
// as error message if the response is an error
// response - i.e. status code >= 400.
//
// If the response status code is < 400, e.g. 200 OK,
// parseErrorResponse returns nil and does not attempt
// to read or close the response body.
//
// If resp is an error response, parseErrorResponse reads
// and closes the response body.
func parseErrorResponse(resp *http.Response) error {
	if resp == nil || resp.StatusCode < 400 {
		return nil
	}
	if resp.Body == nil {
		return NewError(resp.StatusCode, "")
	}
	defer resp.Body.Close()

	const MaxBodySize = 1 << 20
	var size = resp.ContentLength
	if size < 0 || size > MaxBodySize {
		size = MaxBodySize
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") {
		type Response struct {
			Message string `json:"message"`
		}
		var response Response
		if err := json.NewDecoder(io.LimitReader(resp.Body, size)).Decode(&response); err != nil {
			return err
		}
		return NewError(resp.StatusCode, response.Message)
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, io.LimitReader(resp.Body, size)); err != nil {
		return err
	}
	return NewError(resp.StatusCode, sb.String())
}

func parseErrorTrailer(trailer http.Header) error {
	status, err := strconv.Atoi(trailer.Get("Status"))
	if err != nil {
		return fmt.Errorf("kes: invalid HTTP trailer - Status: %q", trailer.Get("Status"))
	}
	if status == http.StatusOK {
		return nil
	}

	errMessage := trailer.Get("Error")
	if errMessage == "" {
		return NewError(status, "")
	}

	type Response struct {
		Message string `json:"message"`
	}
	var response Response
	if err = json.Unmarshal([]byte(errMessage), &response); err != nil {
		return err
	}
	return NewError(status, response.Message)
}
