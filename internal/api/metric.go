// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"
	"time"

	"github.com/minio/kes/internal/auth"
	"github.com/prometheus/common/expfmt"
)

func edgeMetrics(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody int64
		Verify  = true
		Timeout = 15 * time.Second
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

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))
		w.WriteHeader(http.StatusOK)

		config.Metrics.EncodeTo(expfmt.NewEncoder(w, contentType))
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: handler,
	}
}
