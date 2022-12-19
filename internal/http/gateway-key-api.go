// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"path"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/key"
)

func gatewayCreateKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/create/"
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

		var algorithm kes.KeyAlgorithm
		if fips.Enabled || cpu.HasAESGCM() {
			algorithm = kes.AES256_GCM_SHA256
		} else {
			algorithm = kes.XCHACHA20_POLY1305
		}

		key, err := key.Random(algorithm, auth.Identify(r))
		if err != nil {
			Error(w, err)
			return
		}
		if err = config.Keys.Create(r.Context(), name, key); err != nil {
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

func gatewayImportKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = 1 * mem.MiB
		Timeout = 15 * time.Second
	)
	type Request struct {
		Bytes     []byte           `json:"bytes"`
		Algorithm kes.KeyAlgorithm `json:"algorithm"`
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
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(MaxBody))

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err := validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, kes.NewError(http.StatusBadRequest, err.Error()))
			return
		}

		if len(req.Bytes) != key.Len(req.Algorithm) {
			Error(w, kes.NewError(http.StatusBadRequest, "invalid key size"))
			return
		}
		key, err := key.New(req.Algorithm, req.Bytes, auth.Identify(r))
		if err != nil {
			Error(w, err)
			return
		}
		if err = config.Keys.Create(r.Context(), name, key); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
	}
}

func gatewayDescribeKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/key/describe/"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type Response struct {
		Name      string           `json:"name"`
		ID        string           `json:"id,omitempty"`
		Algorithm kes.KeyAlgorithm `json:"algorithm,omitempty"`
		CreatedAt time.Time        `json:"created_at,omitempty"`
		CreatedBy kes.Identity     `json:"created_by,omitempty"`
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
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
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
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func gatewayDeleteKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/key/delete/"
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
		if err := config.Keys.Delete(r.Context(), name); err != nil {
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

func gatewayGenerateKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = 1 * mem.MiB
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Request struct {
		Context []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
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
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Error(w, err)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, int64(MaxBody))

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err := validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		dataKey := make([]byte, 32)
		if _, err = rand.Read(dataKey); err != nil {
			Error(w, err)
			return
		}
		ciphertext, err := key.Wrap(dataKey, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: int64(MaxBody),
		Timeout: Timeout,
	}
}

func gatewayEncryptKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context"` // optional
	}
	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
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

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		ciphertext, err := key.Wrap(req.Plaintext, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Ciphertext: ciphertext,
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

func gatewayDecryptKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
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

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
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

func gatewayBulkDecryptKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = int64(1 * mem.MiB)
		Timeout     = 15 * time.Second
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
		key, err := config.Keys.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}

		var (
			requests  []Request
			responses []Response
		)
		if err = json.NewDecoder(r.Body).Decode(&requests); err != nil {
			Error(w, err)
			return
		}
		if len(requests) > MaxRequests {
			Error(w, kes.NewError(http.StatusBadRequest, "too many ciphertexts"))
			return
		}
		responses = make([]Response, 0, len(requests))
		for _, req := range requests {
			plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
			if err != nil {
				Error(w, err)
				return
			}
			responses = append(responses, Response{
				Plaintext: plaintext,
			})
		}

		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(responses)
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func gatewayListKey(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/x-ndjson"
	)
	type Response struct {
		Name string `json:"name,omitempty"`
		Err  string `json:"error,omitempty"`
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
		iterator, err := config.Keys.List(r.Context())
		if err != nil {
			Error(w, err)
			return
		}

		var (
			hasWritten bool
			encoder    = json.NewEncoder(w)
		)
		for iterator.Next() {
			name := iterator.Name()
			if ok, _ := path.Match(pattern, name); ok && name != "" {
				if !hasWritten {
					w.Header().Set("Content-Type", ContentType)
				}
				hasWritten = true

				if err = encoder.Encode(Response{Name: name}); err != nil {
					return
				}
				if err == http.ErrHandlerTimeout {
					break
				}
				if err != nil {
					encoder.Encode(Response{Err: err.Error()})
					return
				}
			}
		}
		if err = iterator.Close(); err != nil {
			if !hasWritten {
				Error(w, err)
			} else {
				encoder.Encode(Response{Err: err.Error()})
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
