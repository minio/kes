// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/http"
	"time"

	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/log"
)

func edgeErrorLog(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/log/error"
		MaxBody     int64
		Timeout     = 0 * time.Second // No timeout
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Fail(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := log.NewErrEncoder(https.FlushOnWrite(w))
		config.ErrorLog.Add(out)
		defer config.ErrorLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(handler)),
	}
}

func edgeAuditLog(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/log/audit"
		MaxBody     int64
		Timeout     = 0 * time.Second // No timeout
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Fail(w, err)
			return
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := https.FlushOnWrite(w)
		config.AuditLog.Add(out)
		defer config.AuditLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(handler)),
	}
}
