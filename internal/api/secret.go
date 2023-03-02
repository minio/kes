// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"net/http"
	"path"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/secret"
)

func createSecret(config *RouterConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/secret/create/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
		Verify  = true
	)
	type Request struct {
		Type  kes.SecretType `json:"type"`
		Bytes []byte         `json:"bytes"`
	}
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

func describeSecret(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/secret/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Response struct {
		Type      kes.SecretType `json:"type"`
		CreatedAt time.Time      `json:"created_at"`
		ModTime   time.Time      `json:"mod_time"`
		CreatedBy kes.Identity   `json:"created_by"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		secret, err := VSync(config.Vault.RLocker(), func() (secret.Secret, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return secret.Secret{}, err
			}
			return VSync(enclave.RLocker(), func() (secret.Secret, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return secret.Secret{}, err
				}
				return enclave.GetSecret(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Type:      secret.Type(),
			CreatedAt: secret.CreatedAt(),
			ModTime:   secret.ModTime(),
			CreatedBy: secret.CreatedBy(),
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

func readSecret(config *RouterConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/secret/read/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	type Response struct {
		Bytes     []byte         `json:"bytes"`
		Type      kes.SecretType `json:"type"`
		CreatedAt time.Time      `json:"created_at"`
		ModTime   time.Time      `json:"mod_time"`
		CreatedBy kes.Identity   `json:"created_by"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		secret, err := VSync(config.Vault.RLocker(), func() (secret.Secret, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return secret.Secret{}, err
			}
			return VSync(enclave.RLocker(), func() (secret.Secret, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return secret.Secret{}, err
				}
				return enclave.GetSecret(r.Context(), name)
			})
		})
		if err != nil {
			return err
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

func deleteSecret(config *RouterConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/secret/delete/"
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
				return enclave.DeleteSecret(r.Context(), name)
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

func listSecret(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/secret/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
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

				iterator, err := enclave.ListSecrets(r.Context())
				if err != nil {
					return false, err
				}
				defer iterator.Close()

				var hasWritten bool
				encoder := json.NewEncoder(w)
				for iterator.Next() {
					name := iterator.Name()
					if ok, _ := path.Match(pattern, name); !ok || name == "" {
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
