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

func metrics(config *RouterConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				return enclave.VerifyRequest(r)
			})
		}); err != nil {
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
		Handler: handler,
	}
}

func edgeMetrics(config *EdgeRouterConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
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
		Handler: handler,
	}
}
