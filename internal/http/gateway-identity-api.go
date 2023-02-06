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

func gatewayDescribeIdentity(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		IsAdmin   bool         `json:"admin,omitempty"`
		Policy    string       `json:"policy"`
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
		info, err := config.Identities.Get(r.Context(), kes.Identity(name))
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			IsAdmin:   info.IsAdmin,
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

func gatewaySelfDescribeIdentity(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/identity/self/describe"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type InlinePolicy struct {
		Allow     []string     `json:"allow,omitempty"`
		Deny      []string     `json:"deny,omitempty"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	type Response struct {
		Identity   kes.Identity `json:"identity"`
		IsAdmin    bool         `json:"admin,omitempty"`
		PolicyName string       `json:"policy_name,omitempty"`
		CreatedAt  time.Time    `json:"created_at,omitempty"`
		CreatedBy  kes.Identity `json:"created_by,omitempty"`

		Policy InlinePolicy `json:"policy"`
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		identity := auth.Identify(r)
		info, err := config.Identities.Get(r.Context(), identity)
		if err != nil {
			Error(w, err)
			return
		}

		policy := new(auth.Policy)
		if !info.IsAdmin {
			policy, err = config.Policies.Get(r.Context(), info.Policy)
			if err != nil {
				Error(w, err)
				return
			}
		}
		json.NewEncoder(w).Encode(Response{
			Identity:   identity,
			PolicyName: info.Policy,
			IsAdmin:    info.IsAdmin,
			CreatedAt:  info.CreatedAt,
			CreatedBy:  info.CreatedBy,
			Policy: InlinePolicy{
				Allow:     policy.Allow,
				Deny:      policy.Deny,
				CreatedAt: policy.CreatedAt,
				CreatedBy: policy.CreatedBy,
			},
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

func gatewayListIdentities(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Identity  kes.Identity `json:"identity"`
		IsAdmin   bool         `json:"admin"`
		Policy    string       `json:"policy"`
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
		iterator, err := config.Identities.List(r.Context())
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
			info, err := config.Identities.Get(r.Context(), iterator.Identity())
			if err != nil {
				encoder.Encode(Response{Err: err.Error()})
				return
			}
			if !hasWritten {
				w.Header().Set("Content-Type", ContentType)
			}
			err = encoder.Encode(Response{
				Identity:  iterator.Identity(),
				IsAdmin:   info.IsAdmin,
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
