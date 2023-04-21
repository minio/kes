// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/kv"
)

func edgeReady(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodGet
		APIPath = "/v1/ready"
		MaxBody int64
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
		Verify = !c.InsecureSkipAuth
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); Verify && err != nil {
			Fail(w, err)
			return
		}

		_, err := config.Keys.Status(r.Context())
		if _, ok := kv.IsUnreachable(err); ok {
			Fail(w, kes.NewError(http.StatusGatewayTimeout, err.Error()))
			return
		}
		if err != nil {
			Fail(w, kes.NewError(http.StatusBadGateway, err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Verify:  Verify,
		Timeout: Timeout,
		Handler: handler,
	}
}
