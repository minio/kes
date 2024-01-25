// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"net/http"
	"reflect"
)

type responseError struct {
	// ErrorCode is the error code returned by the resource provider if available.
	ErrorCode string

	// StatusCode is the HTTP status code as defined in https://pkg.go.dev/net/http#pkg-constants.
	StatusCode int

	// RawResponse is the underlying HTTP response.
	RawResponse *http.Response

	errorResponse errorResponse
}

// transportErrToResponseError converts a transport error to a ResponseError.
func transportErrToResponseError(terr error) (*responseError, bool) {
	if reflect.TypeOf(terr).String() == "*exported.ResponseError" {
		tv := reflect.ValueOf(terr).Elem()
		ErrorCode := tv.FieldByName("ErrorCode").String()
		StatusCode := int(tv.FieldByName("StatusCode").Int())
		RawResponse, ok := tv.FieldByName("RawResponse").Interface().(*http.Response)
		var errorResponse errorResponse
		if ok {
			errorResponse, _ = parseErrorResponse(RawResponse)
		}
		return &responseError{
			ErrorCode:     ErrorCode,
			StatusCode:    StatusCode,
			RawResponse:   RawResponse,
			errorResponse: errorResponse,
		}, true
	}
	return nil, false
}
