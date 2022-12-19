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

func serverCreateKey(mux *http.ServeMux, config *ServerConfig) API {
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

func serverImportKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/key/import/"
		MaxBody = int64(1 * mem.MiB)
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

func serverDescribeKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Content-Length", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Name:      strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath)),
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

func serverDeleteKey(mux *http.ServeMux, config *ServerConfig) API {
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
				return enclave.DeleteKey(r.Context(), name)
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

func serverGenerateKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodPost
		APIPath     = "/v1/key/generate/"
		MaxBody     = int64(1 * mem.MiB)
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

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		w.WriteHeader(http.StatusOK)
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

func serverEncryptKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
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

func serverDecryptKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(enclave.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}
				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
		if err != nil {
			Error(w, err)
			return
		}

		var req Request
		if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, err)
			return
		}
		plaintext, err := key.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			Error(w, err)
			return
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
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

func serverBulkDecryptKey(mux *http.ServeMux, config *ServerConfig) API {
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
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)

		key, err := VSync(config.Vault.RLocker(), func() (key.Key, error) {
			enclave, err := lookupEnclave(config.Vault, r)
			if err != nil {
				return key.Key{}, err
			}
			return VSync(config.Vault.RLocker(), func() (key.Key, error) {
				if err = enclave.VerifyRequest(r); err != nil {
					return key.Key{}, err
				}

				name := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, APIPath))
				if err = validateName(name); err != nil {
					return key.Key{}, err
				}
				return enclave.GetKey(r.Context(), name)
			})
		})
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
		w.WriteHeader(http.StatusOK)
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

func serverListKey(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/key/list/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
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
