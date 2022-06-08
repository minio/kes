// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"net/http"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
)

func sealVault(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/sys/seal"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog.Log())

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

		sysAdmin, err := config.Vault.SysAdmin(r.Context())
		if err != nil {
			Error(w, err)
			return
		}
		if identity := auth.Identify(r); identity != sysAdmin {
			Error(w, kes.ErrNotAllowed)
			return
		}

		if err = config.Vault.Seal(r.Context()); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}
