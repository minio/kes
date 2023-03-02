// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"path"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/key"
)

func createKey(config *RouterConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/create/"
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

				var algorithm kes.KeyAlgorithm
				if fips.Enabled || cpu.HasAESGCM() {
					algorithm = kes.AES256_GCM_SHA256
				} else {
					algorithm = kes.XCHACHA20_POLY1305
				}

				key, err := key.Random(algorithm, auth.Identify(r))
				if err != nil {
					return err
				}
				return enclave.CreateKey(r.Context(), name, key)
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

func edgeCreateKey(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodPost
		APIPath = "/v1/key/create/"
		MaxBody int64
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		var algorithm kes.KeyAlgorithm
		if fips.Enabled || cpu.HasAESGCM() {
			algorithm = kes.AES256_GCM_SHA256
		} else {
			algorithm = kes.XCHACHA20_POLY1305
		}

		key, err := key.Random(algorithm, auth.Identify(r))
		if err != nil {
			return err
		}
		if err = config.Keys.Create(r.Context(), name, key); err != nil {
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

func importKey(config *RouterConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
		Verify  = true
	)
	type Request struct {
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := Sync(config.Vault.RLocker(), func() error {
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
					return kes.NewError(http.StatusBadRequest, err.Error())
				}
				if len(req.Bytes) != key.Len(req.Algorithm) {
					return kes.NewError(http.StatusBadRequest, "invalid key size")
				}
				key, err := key.New(req.Algorithm, req.Bytes, auth.Identify(r))
				if err != nil {
					return err
				}
				return enclave.CreateKey(r.Context(), name, key)
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

func edgeImportKey(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = 1 * mem.MiB
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Request struct {
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		if len(req.Bytes) != key.Len(req.Algorithm) {
			return kes.NewError(http.StatusBadRequest, "invalid key size")
		}
		key, err := key.New(req.Algorithm, req.Bytes, auth.Identify(r))
		if err != nil {
			return err
		}
		if err = config.Keys.Create(r.Context(), name, key); err != nil {
			return err
		}

		w.WriteHeader(http.StatusOK)
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func describeKey(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Response struct {
		Name      string           `json:"name"`
		ID        string           `json:"id,omitempty"`
		Algorithm kes.KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time        `json:"created_at,omitempty"`
		CreatedBy kes.Identity     `json:"created_by,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Name:      name,
			ID:        key.ID(),
			Algorithm: key.Algorithm(),
			CreatedAt: key.CreatedAt(),
			CreatedBy: key.CreatedBy(),
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

func edgeDescribeKey(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodGet
		APIPath = "/v1/key/describe/"
		MaxBody int64
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Response struct {
		Name      string           `json:"name"`
		ID        string           `json:"id,omitempty"`
		Algorithm kes.KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time        `json:"created_at,omitempty"`
		CreatedBy kes.Identity     `json:"created_by,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Length", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Name:      name,
			ID:        key.ID(),
			Algorithm: key.Algorithm(),
			CreatedAt: key.CreatedAt(),
			CreatedBy: key.CreatedBy(),
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

func deleteKey(config *RouterConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/key/delete/"
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
				return enclave.DeleteKey(r.Context(), name)
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

func edgeDeleteKey(config *EdgeRouterConfig) API {
	var (
		Method  = http.MethodDelete
		APIPath = "/v1/key/delete/"
		MaxBody int64
		Timeout = 15 * time.Second
		Verify  = true
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}
		if err := config.Keys.Delete(r.Context(), name); err != nil {
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

func generateKey(config *RouterConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Request struct {
		Context []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		dataKey := make([]byte, 32)
		if _, err = rand.Read(dataKey); err != nil {
			return err
		}
		ciphertext, err := key.Wrap(dataKey, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
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

func edgeGenerateKey(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = 1 * mem.MiB
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Request struct {
		Context []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		dataKey := make([]byte, 32)
		if _, err = rand.Read(dataKey); err != nil {
			return err
		}
		ciphertext, err := key.Wrap(dataKey, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
		return nil
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
		Verify:  Verify,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func encryptKey(config *RouterConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context"` // optional
	}
	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		ciphertext, err := key.Wrap(req.Plaintext, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Ciphertext: ciphertext,
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

func edgeEncryptKey(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodPost
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context"` // optional
	}
	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		ciphertext, err := key.Wrap(req.Plaintext, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Ciphertext: ciphertext,
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

func decryptKey(config *RouterConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
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

func edgeDecryptKey(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodPost
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return err
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
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

func bulkDecryptKey(config *RouterConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
		MaxRequests = 1000 // For now, we limit the number of decryption requests in a single API call to 1000.
	)
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(config.Vault.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			return err
		}

		var (
			requests  []Request
			responses []Response
		)
		if err = json.NewDecoder(r.Body).Decode(&requests); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		if len(requests) > MaxRequests {
			return kes.NewError(http.StatusBadRequest, "too many ciphertexts")
		}
		responses = make([]Response, 0, len(requests))
		for _, req := range requests {
			plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
			if err != nil {
				return err
			}
			responses = append(responses, Response{
				Plaintext: plaintext,
			})
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responses)
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

func edgeBulkDecryptKey(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
		MaxRequests = 1000 // For now, we limit the number of decryption requests in a single API call to 1000.
	)
	if c, ok := config.APIConfig[APIPath]; ok {
		if c.Timeout > 0 {
			Timeout = c.Timeout
		}
	}
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			return err
		}
		var (
			requests  []Request
			responses []Response
		)
		if err = json.NewDecoder(r.Body).Decode(&requests); err != nil {
			return kes.NewError(http.StatusBadRequest, err.Error())
		}
		if len(requests) > MaxRequests {
			return kes.NewError(http.StatusBadRequest, "too many ciphertexts")
		}
		responses = make([]Response, 0, len(requests))
		for _, req := range requests {
			plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
			if err != nil {
				return err
			}
			responses = append(responses, Response{
				Plaintext: plaintext,
			})
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responses)
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

func listKey(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Name      string           `json:"name,omitempty"`
		ID        string           `json:"id,omitempty"`
		Algorithm kes.KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time        `json:"created_at,omitempty"`
		CreatedBy kes.Identity     `json:"created_by,omitempty"`

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

				iterator, err := enclave.ListKeys(r.Context())
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
					key, err := enclave.GetKey(r.Context(), iterator.Name())
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
						ID:        key.ID(),
						Algorithm: key.Algorithm(),
						CreatedAt: key.CreatedAt(),
						CreatedBy: key.CreatedBy(),
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

func edgeListKey(config *EdgeRouterConfig) API {
	var (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
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
		Name string `json:"name,omitempty"`
		Err  string `json:"error,omitempty"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		pattern, err := patternFromRequest(r, APIPath)
		if err != nil {
			return err
		}
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			return err
		}

		iterator, err := config.Keys.List(r.Context())
		if err != nil {
			return err
		}
		defer iterator.Close()

		var (
			hasWritten bool
			encoder    = json.NewEncoder(w)
		)
		for iterator.Next() {
			name := iterator.Name()
			if ok, _ := path.Match(pattern, name); !ok || name == "" {
				continue
			}
			if !hasWritten {
				w.Header().Set("Content-Type", ContentType)
			}
			hasWritten = true

			if err = encoder.Encode(Response{Name: name}); err != nil {
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
