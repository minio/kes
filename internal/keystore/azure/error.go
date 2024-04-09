// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"encoding/json"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// errorResponse is a KeyVault secrets API error response.
type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Inner   struct {
			Code string `json:"code"`
		} `json:"innererror"`
	} `json:"error"`
}

// transportErrToStatus converts a transport error to a Status.
func transportErrToStatus(err error) (status, error) {
	var rerr *azcore.ResponseError
	if errors.As(err, &rerr) {
		var errorResponse errorResponse
		if rerr.RawResponse != nil {
			err = json.NewDecoder(rerr.RawResponse.Body).Decode(&errorResponse)
			if err != nil {
				return status{}, err
			}
		}
		return status{
			ErrorCode:  errorResponse.Error.Inner.Code,
			StatusCode: rerr.StatusCode,
			Message:    errorResponse.Error.Message,
		}, nil
	}
	return status{}, err
}
