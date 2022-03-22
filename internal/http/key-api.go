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
	"github.com/minio/kes/internal/key"
	"github.com/secure-io/sio-go/sioutil"
)

func createKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		key := key.New(sioutil.MustRandom(key.Size))
		if err = enclave.CreateKey(r.Context(), name, key); err != nil {
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

func importKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = 1 << 20
		Timeout = 15 * time.Second
	)
	type Request struct {
		Bytes []byte `json:"bytes"`
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		if len(req.Bytes) != key.Size {
			Error(w, kes.NewError(http.StatusBadRequest, "invalid key size"))
			return
		}
		if err = enclave.CreateKey(r.Context(), name, key.New(req.Bytes)); err != nil {
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

func deleteKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		if err = enclave.DeleteKey(r.Context(), name); err != nil {
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

func generateKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = 1 << 20
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := enclave.GetKey(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		dataKey, err := sioutil.Random(32)
		if err != nil {
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
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func encryptKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/encrypt/"
		MaxBody     = 1 << 20
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := enclave.GetKey(r.Context(), name)
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

func decryptKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/decrypt/"
		MaxBody     = 1 << 20
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		key, err := enclave.GetKey(r.Context(), name)
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

func bulkDecryptKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/bulk/decrypt/"
		MaxBody     = 1 << 20
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validateName(name); err != nil {
			Error(w, err)
			return
		}
		key, err := enclave.GetKey(r.Context(), name)
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

func listKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		enclave, err := lookupEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}

		pattern := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
		if err = validatePattern(pattern); err != nil {
			Error(w, err)
			return
		}
		iterator, err := enclave.ListKeys(r.Context())
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
		if err = iterator.Err(); err != nil {
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
