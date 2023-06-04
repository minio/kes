// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"
	"strings"
)

// Router is an HTTP handler that implements the KES API.
//
// It routes incoming HTTP requests and invokes the
// corresponding API handlers.
type Router struct {
	Handler http.Handler

	APIs []API
}

// ServeHTTP dispatches the request to the API handler whose
// pattern most matches the request URL.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, "/") { // Ensure URL paths start with a '/'
		req.URL.Path = "/" + req.URL.Path
	}
	r.Handler.ServeHTTP(w, req)
}
