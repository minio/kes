// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// KES server API errors
var (
	// ErrNotAllowed is returned by a KES server when a client has
	// not sufficient permission to perform the API operation.
	ErrNotAllowed = NewError(http.StatusForbidden, "not authorized: insufficient permissions")

	// ErrKeyNotFound is returned by a KES server when a client tries to
	// access or use a cryptographic key which does not exist.
	ErrKeyNotFound = NewError(http.StatusNotFound, "key does not exist")

	// ErrKeyExists is returned by a KES server when a client tries
	// to create a cryptographic key which already exists.
	ErrKeyExists = NewError(http.StatusBadRequest, "key already exists")

	// ErrPolicyNotFound is returned by a KES server when a client
	// tries to access a policy which does not exist.
	ErrPolicyNotFound = NewError(http.StatusNotFound, "policy does not exist")

	// ErrDecrypt is returned by a KES server when it fails to decrypt
	// a ciphertext. It may occur when a client uses the wrong key or
	// the ciphertext has been (maliciously) modified.
	ErrDecrypt = NewError(http.StatusBadRequest, "decryption failed: ciphertext is not authentic")

	// ErrEnclaveExists is returned by a KES server when a client tries
	// to create an enclave that already exists.
	ErrEnclaveExists = NewError(http.StatusBadRequest, "enclave already exists")

	// ErrEnclaveNotFound is returned by a KES server when a client tries
	// to access an enclave which does not exist.
	ErrEnclaveNotFound = NewError(http.StatusNotFound, "enclave does not exist")
)

// Error is a KES server API error.
type Error struct {
	code    int
	message string
}

// NewError returns a new Error with the given
// HTTP status code and error message.
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
	size := resp.ContentLength
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

		// TODO(aead): Remove the backwards-compatibility error checks once enough of the
		// KES server ecosystem has updated.
		if resp.StatusCode == http.StatusBadRequest && response.Message == "key does already exist" {
			return ErrKeyExists
		}
		if resp.StatusCode == http.StatusForbidden && response.Message == "prohibited by policy" {
			return ErrNotAllowed
		}
		return NewError(resp.StatusCode, response.Message)
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, io.LimitReader(resp.Body, size)); err != nil {
		return err
	}
	return NewError(resp.StatusCode, sb.String())
}
