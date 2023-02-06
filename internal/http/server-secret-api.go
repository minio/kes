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
	"github.com/minio/kes/internal/secret"
)

func serverCreateSecret(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/secret/create/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
	)
	type Request struct {
		Type  kes.SecretType `json:"type"`
		Bytes []byte         `json:"bytes"`
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
				if req.Type != kes.SecretGeneric { // Currently, we only support generic secrets
					return kes.NewError(http.StatusBadRequest, "unsupported secret type '"+req.Type.String()+"'")
				}

				secret := secret.NewSecret(req.Bytes, auth.Identify(r))
				return enclave.CreateSecret(r.Context(), name, secret)
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

func serverDescribeSecret(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/secret/describe/"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type Response struct {
		Type      kes.SecretType `json:"type"`
		CreatedAt time.Time      `json:"created_at"`
		ModTime   time.Time      `json:"mod_time"`
		CreatedBy kes.Identity   `json:"created_by"`
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

		secret, err := VSync(config.Vault.RLocker(), func() (secret.Secret, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return secret.Secret{}, err
			}
			return VSync(enclave.RLocker(), func() (secret.Secret, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return secret.Secret{}, err
				}

				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return secret.Secret{}, err
				}
				return enclave.GetSecret(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Type:      secret.Type(),
			CreatedAt: secret.CreatedAt(),
			ModTime:   secret.ModTime(),
			CreatedBy: secret.CreatedBy(),
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

func serverReadSecret(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/secret/read/"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type Response struct {
		Bytes     []byte         `json:"bytes"`
		Type      kes.SecretType `json:"type"`
		CreatedAt time.Time      `json:"created_at"`
		ModTime   time.Time      `json:"mod_time"`
		CreatedBy kes.Identity   `json:"created_by"`
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

		secret, err := VSync(config.Vault.RLocker(), func() (secret.Secret, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return secret.Secret{}, err
			}
			return VSync(enclave.RLocker(), func() (secret.Secret, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return secret.Secret{}, err
				}

				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return secret.Secret{}, err
				}
				return enclave.GetSecret(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Bytes:     secret.Bytes(),
			Type:      secret.Type(),
			CreatedAt: secret.CreatedAt(),
			ModTime:   secret.ModTime(),
			CreatedBy: secret.CreatedBy(),
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

func serverDeleteSecret(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/secret/delete/"
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
				return enclave.DeleteSecret(r.Context(), name)
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

func serverListSecrets(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/secret/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Name      string         `json:"name,omitempty"`
		Type      kes.SecretType `json:"type,omitempty"`
		CreatedAt time.Time      `json:"created_at,omitempty"`
		ModTime   time.Time      `json:"mod_time,omitempty"`
		CreatedBy kes.Identity   `json:"created_by,omitempty"`

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

				iterator, err := enclave.ListSecrets(r.Context())
				if err != nil {
					return false, err
				}
				defer iterator.Close()

				var hasWritten bool
				encoder := json.NewEncoder(w)
				for iterator.Next() {
					if ok, _ := path.Match(pattern, iterator.Name()); !ok || iterator.Name() == "" {
						continue
					}
					secret, err := enclave.GetSecret(r.Context(), iterator.Name())
					if err != nil {
						return hasWritten, err
					}
					if !hasWritten {
						hasWritten = true
						w.Header().Set("Content-Type", ContentType)
						w.WriteHeader(http.StatusOK)
					}

					err = encoder.Encode(Response{
						Name:      iterator.Name(),
						CreatedAt: secret.CreatedAt(),
						ModTime:   secret.ModTime(),
						CreatedBy: secret.CreatedBy(),
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
