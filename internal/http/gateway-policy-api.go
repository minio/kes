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
	"github.com/minio/kes/internal/auth"
)

func gatewayDescribePolicy(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog)

		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		if err := normalizeURL(r.URL, APIPath); err != nil {
			Error(w, err)
			return
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err := validateName(name); err != nil {
			Error(w, err)
			return
		}
		policy, err := config.Policies.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
	}
	mux.HandleFunc(APIPath, timeout(Timeout, config.Metrics.Count(config.Metrics.Latency(handler))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func gatewayReadPolicy(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/read/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Allow     []string     `json:"allow,omitempty"`
		Deny      []string     `json:"deny,omitempty"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog)

		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		if err := normalizeURL(r.URL, APIPath); err != nil {
			Error(w, err)
			return
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err := validateName(name); err != nil {
			Error(w, err)
			return
		}
		policy, err := config.Policies.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
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

func gatewayListPolicy(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Name      string       `json:"name"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`

		Err string `json:"error,omitempty"`
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog)

		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		if err := normalizeURL(r.URL, APIPath); err != nil {
			Error(w, err)
			return
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		pattern := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err := validatePattern(pattern); err != nil {
			Error(w, err)
			return
		}
		iterator, err := config.Policies.List(r.Context())
		if err != nil {
			Error(w, err)
			return
		}

		var hasWritten bool
		encoder := json.NewEncoder(w)
		w.Header().Set("Content-Type", ContentType)
		for iterator.Next() {
			if ok, _ := path.Match(pattern, iterator.Name()); !ok {
				continue
			}

			policy, err := config.Policies.Get(r.Context(), iterator.Name())
			if err != nil {
				encoder.Encode(Response{Err: err.Error()})
				return
			}
			err = encoder.Encode(Response{
				Name:      iterator.Name(),
				CreatedAt: policy.CreatedAt,
				CreatedBy: policy.CreatedBy,
			})
			if err != nil {
				return
			}
			hasWritten = true
		}
		if err = iterator.Close(); err != nil {
			encoder.Encode(Response{Err: err.Error()})
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
