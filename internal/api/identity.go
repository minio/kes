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

func describeIdentity(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Response struct {
		IsAdmin   bool         `json:"admin,omitempty"`
		Policy    string       `json:"policy"`
		CreatedAt time.Time    `json:"created_at,omitempty"`
		CreatedBy kes.Identity `json:"created_by,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		info, err := VSync(config.Vault.RLocker(), func() (auth.IdentityInfo, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return auth.IdentityInfo{}, err
			}
			return VSync(enclave.RLocker(), func() (auth.IdentityInfo, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return auth.IdentityInfo{}, err
				}
				return enclave.GetIdentity(r.Context(), kes.Identity(name))
			})
		})
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			IsAdmin:   info.IsAdmin,
			Policy:    info.Policy,
			CreatedAt: info.CreatedAt,
			CreatedBy: info.CreatedBy,
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

func edgeDescribeIdentity(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/describe/"
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
		IsAdmin   bool         `json:"admin,omitempty"`
		Policy    string       `json:"policy"`
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

		info, err := config.Identities.Get(r.Context(), kes.Identity(name))
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			IsAdmin:   info.IsAdmin,
			Policy:    info.Policy,
			CreatedAt: info.CreatedAt,
			CreatedBy: info.CreatedBy,
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

func selfDescribeIdentity(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/self/describe"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = false
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
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		response, err := VSync(config.Vault.RLocker(), func() (Response, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
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
			return err
		}

		w.Header().Add("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
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

func edgeSelfDescribeIdentity(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/self/describe"
		MaxBody     int64
		Timeout     = 15 * time.Second
		Verify      = false
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
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
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		identity := auth.Identify(r)
		info, err := config.Identities.Get(r.Context(), identity)
		if err != nil {
			return err
		}
		policy := new(auth.Policy)
		if !info.IsAdmin {
			policy, err = config.Policies.Get(r.Context(), info.Policy)
			if err != nil {
				return err
			}
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
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

func deleteIdentity(config *RouterConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/identity/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		if err = Sync(config.Vault.RLocker(), func() error {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.Locker(), func() error {
				if err = enclave.VerifyRequest(r); err != nil {
					return err
				}
				admin, err := config.Vault.Admin(r.Context())
				if err != nil {
					return err
				}

				identity := kes.Identity(name)
				if admin == identity {
					return kes.NewError(http.StatusBadRequest, "cannot delete system admin")
				}
				return enclave.DeleteIdentity(r.Context(), identity)
			})
		}); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
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

func listIdentity(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
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
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		pattern, err := patternFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		hasWritten, err := VSync(config.Vault.RLocker(), func() (bool, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return false, err
			}
			return VSync(enclave.RLocker(), func() (bool, error) {
				if err = enclave.VerifyRequest(r); err != nil {
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
			if hasWritten {
				json.NewEncoder(w).Encode(Response{Err: err.Error()})
				return nil
			}
			return err
		}
		if !hasWritten {
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

func edgeListIdentity(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/identity/list/"
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
		Identity  kes.Identity `json:"identity"`
		IsAdmin   bool         `json:"admin"`
		Policy    string       `json:"policy"`
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

		iterator, err := config.Identities.List(r.Context())
		if err != nil {
			return err
		}
		defer iterator.Close()

		var (
			encoder    = json.NewEncoder(w)
			hasWritten bool
		)
		for iterator.Next() {
			if ok, _ := path.Match(pattern, iterator.Identity().String()); !ok {
				continue
			}
			if !hasWritten {
				w.Header().Set("Content-Type", ContentType)
			}
			hasWritten = true

			info, err := config.Identities.Get(r.Context(), iterator.Identity())
			if err != nil {
				encoder.Encode(Response{Err: err.Error()})
				return nil
			}

			if err = encoder.Encode(Response{
				Identity:  iterator.Identity(),
				IsAdmin:   info.IsAdmin,
				Policy:    info.Policy,
				CreatedAt: info.CreatedAt,
				CreatedBy: info.CreatedBy,
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
