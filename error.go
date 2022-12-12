// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"aead.dev/mem"
)

// KES server API errors
var (
	// ErrSealed is returned by a KES server that got sealed.
	// Such a KES server will not process any requests until
	// unsealed again.
	ErrSealed = NewError(http.StatusForbidden, "system is sealed")

	// ErrNotAllowed is returned by a KES server when a client has
	// not sufficient permission to perform the API operation.
	ErrNotAllowed = NewError(http.StatusForbidden, "not authorized: insufficient permissions")

	// ErrKeyNotFound is returned by a KES server when a client tries to
	// access or use a cryptographic key which does not exist.
	ErrKeyNotFound = NewError(http.StatusNotFound, "key does not exist")

	// ErrKeyExists is returned by a KES server when a client tries
	// to create a cryptographic key which already exists.
	ErrKeyExists = NewError(http.StatusBadRequest, "key already exists")

	// ErrSecretNotFound is returned by a KES server when a client tries to
	// access a secret which does not exist.
	ErrSecretNotFound = NewError(http.StatusNotFound, "secret does not exist")

	// ErrKeyExists is returned by a KES server when a client tries
	// to create a secret which already exists.
	ErrSecretExists = NewError(http.StatusNotFound, "secret already exists")

	// ErrPolicyNotFound is returned by a KES server when a client
	// tries to access a policy which does not exist.
	ErrPolicyNotFound = NewError(http.StatusNotFound, "policy does not exist")

	// ErrPolicyNotFound is returned by a KES server when a client
	// tries to access a policy which does not exist.
	ErrIdentityNotFound = NewError(http.StatusNotFound, "identity does not exist")

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

// IsConnError reports whether err is or wraps a
// ConnError. In this case, it returns the ConnError.
func IsConnError(err error) (*ConnError, bool) {
	var cErr *ConnError
	if errors.As(err, &cErr) {
		return cErr, true
	}
	return nil, false
}

// ConnError is a network connection error. It is returned
// by a Client or Enclave when a request fails due to a
// network or connection issue. For example, a temporary
// DNS error.
//
// Calling code may check whether a returned error is
// of type ConnError:
//
//	if cErr, ok := kes.IsConnError(err) {
//	   // TODO: handle connection error
//	}
type ConnError struct {
	Host string // The host that couldn't be reached
	Err  error  // The underlying error, if any.
}

var _ net.Error = (*ConnError)(nil) // compiler check

// Error returns the string representation of the ConnError.
func (c *ConnError) Error() string { return fmt.Sprintf("kes: connection error: %v", c.Err) }

// Unwarp returns the underlying connection error.
func (c *ConnError) Unwrap() error { return c.Err }

// Timeout reports whether the error is caused
// by a timeout.
func (c *ConnError) Timeout() bool {
	if c.Err == nil {
		return false
	}
	if errors.Is(c.Err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(c.Err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

// Temporary returns false. It is implemented
// such that ConnError implements the net.Error
// interface.
//
// Deprecated: See the net.Error documentation
func (c *ConnError) Temporary() bool { return false }

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

	const MaxBodySize = 1 * mem.MiB
	size := mem.Size(resp.ContentLength)
	if size < 0 || size > MaxBodySize {
		size = MaxBodySize
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") {
		type Response struct {
			Message string `json:"message"`
		}
		var response Response
		if err := json.NewDecoder(mem.LimitReader(resp.Body, size)).Decode(&response); err != nil {
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
	if _, err := io.Copy(&sb, mem.LimitReader(resp.Body, size)); err != nil {
		return err
	}
	return NewError(resp.StatusCode, sb.String())
}
