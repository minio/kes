// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package errors

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// New returns a new error that formats as the
// given message and has a Status() method that
// returns the given code.
//
// All errors with the same code and message
// returned by New are equal. In particular,
//  err1 := New(400, "a message")
//  err2 := New(400, "a message")
//  err1 == err2                 // this will be true
func New(code int, message string) error {
	return statusError{
		code: code,
		msg:  message,
	}
}

// HasStatus returns true if err has a Status() int
// method. More precisely, if err implements
//  interface { Status() int }
func HasStatus(err error) bool {
	_, ok := err.(interface{ Status() int })
	return ok
}

type statusError struct {
	code int
	msg  string
}

func (e statusError) Status() int   { return e.code }
func (e statusError) Error() string { return e.msg }

// Respond sends the given err as JSON to w.
//
// If err has a Status() method it sets the response
// status code to err.Status(). Otherwise, the
// response status code will be 500 (internal server error).
//
// If err is nil Respond sets the response status code to
// 500 and sends an empty JSON object - "{}" - to w.
func Respond(w http.ResponseWriter, err error) error {
	var status = http.StatusInternalServerError
	if e, ok := err.(interface{ Status() int }); ok {
		status = e.Status()
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	const (
		emptyMsg = `{}`
		msgFmt   = `{"message":"%v"}`
	)
	if err == nil {
		_, err = io.WriteString(w, emptyMsg)
	} else {
		_, err = io.WriteString(w, fmt.Sprintf(msgFmt, err))
	}
	return err
}

// ParseResponse returns an error containing
// the response status code and response body
// as error message if the response is an error
// response - i.e. status code >= 400.
//
// If the response status code is < 400, e.g. 200 OK,
// ParseResponse returns nil and does not attempt to
// read or close the responde body.
//
// If resp is an error response, ParseResponse reads
// and closes the response body.
func ParseResponse(resp *http.Response) error {
	if resp.StatusCode < 400 {
		return nil
	}
	if resp.Body == nil {
		return New(resp.StatusCode, "")
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
		return New(resp.StatusCode, response.Message)
	}
	var sb strings.Builder
	if _, err := io.CopyN(&sb, resp.Body, size); err != nil {
		return err
	}
	return New(resp.StatusCode, sb.String())
}
