// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
	"time"

	xlog "github.com/minio/kes/internal/log"
)

func serverErrorLog(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/error"
		MaxBody     = 0
		Timeout     = 0 * time.Second // No timeout
		ContentType = "application/x-ndjson"
	)

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		if err := normalizeURL(r.URL, APIPath); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				return enclave.VerifyRequest(r)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := xlog.NewErrEncoder(NewFlushWriter(w))
		config.ErrorLog.Add(out)
		defer config.ErrorLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
	}
	mux.HandleFunc(APIPath, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func serverAuditLog(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/log/audit"
		MaxBody     = 0
		Timeout     = 0 * time.Second // No timeout
		ContentType = "application/x-ndjson"
	)

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		if err := normalizeURL(r.URL, APIPath); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				return enclave.VerifyRequest(r)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)

		out := NewFlushWriter(w)
		config.AuditLog.Add(out)
		defer config.AuditLog.Remove(out)

		<-r.Context().Done() // Wait for the client to close the connection
	}
	mux.HandleFunc(APIPath, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}
