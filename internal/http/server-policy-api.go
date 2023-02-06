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

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
)

func serverDescribePolicy(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		policy, err := VSync(config.Vault.RLocker(), func() (auth.Policy, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return auth.Policy{}, err
			}
			return VSync(enclave.RLocker(), func() (auth.Policy, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return auth.Policy{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return auth.Policy{}, err
				}
				return enclave.GetPolicy(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
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

func serverAssignPolicy(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/policy/assign/"
		MaxBody = int64(1 * mem.KiB)
		Timeout = 15 * time.Second
	)
	type Request struct {
		Identity kes.Identity `json:"identity"`
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

				var req Request
				if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
					return err
				}
				if err = validateName(req.Identity.String()); err != nil {
					return err
				}
				if req.Identity.IsUnknown() {
					return kes.NewError(http.StatusBadRequest, "identity is unknown")
				}
				if self := auth.Identify(r); self == req.Identity {
					return kes.NewError(http.StatusForbidden, "identity cannot assign policy to itself")
				}
				admin, err := config.Vault.Admin(r.Context())
				if err != nil {
					return err
				}
				if admin == req.Identity {
					return kes.NewError(http.StatusBadRequest, "cannot assign policy to system admin")
				}
				return enclave.AssignPolicy(r.Context(), name, req.Identity)
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

func serverReadPolicy(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		policy, err := VSync(config.Vault.RLocker(), func() (auth.Policy, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return auth.Policy{}, err
			}
			return VSync(enclave.RLocker(), func() (auth.Policy, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return auth.Policy{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return auth.Policy{}, err
				}
				return enclave.GetPolicy(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
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

func serverWritePolicy(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/policy/write/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
	)
	type Request struct {
		Allow []string `json:"allow,omitempty"`
		Deny  []string `json:"deny,omitempty"`
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

				var req Request
				if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
					return err
				}
				return enclave.SetPolicy(r.Context(), name, auth.Policy{
					Allow:     req.Allow,
					Deny:      req.Deny,
					CreatedAt: time.Now().UTC(),
					CreatedBy: auth.Identify(r),
				})
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

func serverDeletePolicy(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/policy/delete/"
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
				return enclave.DeletePolicy(r.Context(), name)
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

func serverListPolicy(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				if err = enclave.VerifyRequest(r); err != nil {
					return err
				}
				pattern := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validatePattern(pattern); err != nil {
					return err
				}
				iterator, err := enclave.ListPolicies(r.Context())
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

					policy, err := enclave.GetPolicy(r.Context(), iterator.Name())
					if err != nil {
						encoder.Encode(Response{Err: err.Error()})
						return nil
					}
					err = encoder.Encode(Response{
						Name:      iterator.Name(),
						CreatedAt: policy.CreatedAt,
						CreatedBy: policy.CreatedBy,
					})
					if err != nil {
						return nil
					}
					hasWritten = true
				}
				if err = iterator.Close(); err != nil {
					encoder.Encode(Response{Err: err.Error()})
					return nil
				}
				if !hasWritten {
					w.WriteHeader(http.StatusOK)
				}
				return nil
			})
		})
		if err != nil {
			Error(w, err)
			return
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
