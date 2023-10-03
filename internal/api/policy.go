// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"net/http"
	"path"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
)

func edgeDescribePolicy(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/describe/"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Response struct {
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		policy, err := config.Policies.Get(r.Context(), name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func edgeReadPolicy(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/read/"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Response struct {
		Allow     map[string]kes.Rule `json:"allow,omitempty"`
		Deny      map[string]kes.Rule `json:"deny,omitempty"`
		CreatedAt time.Time           `json:"created_at,omitempty"`
		CreatedBy kes.Identity        `json:"created_by,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		policy, err := config.Policies.Get(r.Context(), name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func edgeListPolicy(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/policy/list/"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Response struct {
		Name      string       `json:"name"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`

		Err string `json:"error,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		pattern, err := patternFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		iterator, err := config.Policies.List(r.Context())
		if err != nil {
			return err
		}
		defer iterator.Close()

		var hasWritten bool
		encoder := json.NewEncoder(w)
		w.Header().Set("Content-Type", ContentType)
		for iterator.Next() {
			if ok, _ := path.Match(pattern, iterator.Name()); !ok {
				continue
			}
			if !hasWritten {
				w.Header().Set("Content-Type", ContentType)
			}
			hasWritten = true

			policy, err := config.Policies.Get(r.Context(), iterator.Name())
			if err != nil {
				encoder.Encode(Response{Err: err.Error()})
				return nil
			}
			if err = encoder.Encode(Response{
				Name:      iterator.Name(),
				CreatedAt: policy.CreatedAt,
				CreatedBy: policy.CreatedBy,
			}); err != nil {
				return nil
			}
		}
		if err = iterator.Close(); err != nil {
			if hasWritten {
				encoder.Encode(Response{Err: err.Error()})
				return nil
			}
			return err
		}
		if !hasWritten {
			w.Header().Set("Content-Type", ContentType)
			w.WriteHeader(http.StatusOK)
		}
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}
