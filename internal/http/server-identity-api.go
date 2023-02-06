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

func serverDescribeIdentity(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		info, err := VSync(config.Vault.RLocker(), func() (auth.IdentityInfo, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return auth.IdentityInfo{}, err
			}
			return VSync(enclave.RLocker(), func() (auth.IdentityInfo, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return auth.IdentityInfo{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return auth.IdentityInfo{}, err
				}
				return enclave.GetIdentity(r.Context(), kes.Identity(name))
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
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

func serverSelfDescribeIdentity(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/self/describe"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
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

		response, err := VSync(config.Vault.RLocker(), func() (Response, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return Response{}, err
			}
			return VSync(enclave.RLocker(), func() (Response, error) {
				identity := auth.Identify(r)
				info, err := enclave.GetIdentity(r.Context(), identity)
				if err != nil {
					return Response{}, err
				}
				policy := auth.Policy{}
				if !info.IsAdmin {
					policy, err = enclave.GetPolicy(r.Context(), info.Policy)
					if err != nil {
						return Response{}, err
					}
				}
				return Response{
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
				}, nil
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		w.Header().Add("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func serverDeleteIdentity(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/identity/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
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

		err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.Locker(), func() error {
				if err = enclave.VerifyRequest(r); err != nil {
					return err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return err
				}
				identity := kes.Identity(name)
				admin, err := config.Vault.Admin(r.Context())
				if err != nil {
					return err
				}
				if admin == identity {
					return kes.NewError(http.StatusBadRequest, "cannot delete system admin")
				}
				return enclave.DeleteIdentity(r.Context(), identity)
			})
		})
		if err != nil {
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

func serverListIdentity(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		hasWritten, err := VSync(config.Vault.RLocker(), func() (bool, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return false, err
			}
			return VSync(enclave.RLocker(), func() (bool, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return false, err
				}
				pattern := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validatePattern(pattern); err != nil {
					return false, err
				}
				iterator, err := enclave.ListIdentities(r.Context())
				if err != nil {
					return false, err
				}
				defer iterator.Close()

				var hasWritten bool
				encoder := json.NewEncoder(w)
				for iterator.Next() {
					if ok, _ := path.Match(pattern, iterator.Identity().String()); !ok {
						continue
					}
					info, err := enclave.GetIdentity(r.Context(), iterator.Identity())
					if err != nil {
						return hasWritten, err
					}
					if !hasWritten {
						hasWritten = true
						w.Header().Set("Content-Type", ContentType)
						w.WriteHeader(http.StatusOK)
					}

					err = encoder.Encode(Response{
						Identity:  iterator.Identity(),
						IsAdmin:   info.IsAdmin,
						Policy:    info.Policy,
						CreatedAt: info.CreatedAt,
						CreatedBy: info.CreatedBy,
					})
					if err != nil {
						return hasWritten, err
					}
				}
				return hasWritten, iterator.Close()
			})
		})
		if err != nil {
			if !hasWritten {
				Error(w, err)
			} else {
				json.NewEncoder(w).Encode(Response{Err: err.Error()})
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
