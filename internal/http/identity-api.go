// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/minio/kes"
)

func describeIdentity(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Identity  kes.Identity `json:"identity"`
		Policy    string       `json:"policy"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
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

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}
		info, err := enclave.GetIdentity(r.Context(), kes.Identity(name))
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Identity:  kes.Identity(name),
			Policy:    info.Policy,
			CreatedAt: info.CreatedAt,
			CreatedBy: info.CreatedBy,
		})
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func deleteIdentity(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/identity/forget/"
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

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}
		if err = enclave.DeleteIdentity(r.Context(), kes.Identity(name)); err != nil {
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

func listIdentity(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Identity  kes.Identity `json:"identity"`
		Policy    string       `json:"policy"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`

		Err string `json:"error,omitempty"`
	}
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

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		pattern := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validatePattern(pattern); err != nil {
			Error(w, err)
			return
		}
		iterator, err := enclave.ListIdentities(r.Context())
		if err != nil {
			Error(w, err)
			return
		}
		var (
			encoder    = json.NewEncoder(w)
			hasWritten bool
		)
		for iterator.Next() {
			if ok, _ := path.Match(pattern, iterator.Identity().String()); !ok {
				continue
			}
			info, err := enclave.GetIdentity(r.Context(), iterator.Identity())
			if err != nil {
				encoder.Encode(Response{Err: err.Error()})
				return
			}
			if !hasWritten {
				w.Header().Set("Content-Type", ContentType)
			}
			err = encoder.Encode(Response{
				Identity:  iterator.Identity(),
				Policy:    info.Policy,
				CreatedAt: info.CreatedAt,
				CreatedBy: info.CreatedBy,
			})
			if err != nil {
				return
			}
			hasWritten = true
		}
		if err = iterator.Close(); err != nil {
			if hasWritten {
				encoder.Encode(Response{Err: err.Error()})
			} else {
				Error(w, err)
			}
			return
		}
		if !hasWritten {
			w.WriteHeader(http.StatusOK)
		}
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}
