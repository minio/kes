// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package azure

import (
	"encoding/json"
	"net/http"

	"aead.dev/mem"
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

// parseErrorResponse parses the response body as
// KeyVault secrets API error response.
func parseErrorResponse(resp *http.Response) (errorResponse, error) {
	const MaxSize = 1 * mem.MiB
	limit := mem.Size(resp.ContentLength)
	if limit < 0 || limit > MaxSize {
		limit = MaxSize
	}

	var response errorResponse
	if err := json.NewDecoder(mem.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return errorResponse{}, err
	}
	return response, nil
}
