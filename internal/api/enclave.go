// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/sys"
)

func createEnclave(config *RouterConfig) API {
	const (
		Method  = http.MethodPost
		APIPath = "/v1/enclave/create/"
		MaxBody = int64(1 * mem.MiB)
		Timeout = 15 * time.Second
		Verify  = true
	)
	type Request struct {
		Admin kes.Identity `json:"admin"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		if err = Sync(config.Vault.Locker(), func() error {
			sysAdmin, err := config.Vault.Admin(r.Context())
			if err != nil {
				return err
			}
			if identity := auth.Identify(r); identity != sysAdmin {
				return kes.ErrNotAllowed
			}

			var req Request
			if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
				return err
			}
			if err = verifyName(req.Admin.String()); err != nil {
				return err
			}
			if req.Admin.IsUnknown() {
				return kes.NewError(http.StatusBadRequest, "identity is unknown")
			}
			if req.Admin == sysAdmin {
				return kes.NewError(http.StatusBadRequest, "admin identity cannot be system admin")
			}
			if _, err = config.Vault.CreateEnclave(r.Context(), name, req.Admin); err != nil {
				return err
			}
			return nil
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

func describeEnclave(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/enclave/describe/"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		Verify      = true
		ContentType = "application/json"
	)
	type Response struct {
		Name      string       `json:"name"`
		CreatedAt time.Time    `json:"created_at"`
		CreatedBy kes.Identity `json:"created_by"`
	}
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		info, err := VSync(config.Vault.RLocker(), func() (sys.EnclaveInfo, error) {
			sysAdmin, err := config.Vault.Admin(r.Context())
			if err != nil {
				return sys.EnclaveInfo{}, err
			}
			if identity := auth.Identify(r); identity != sysAdmin {
				return sys.EnclaveInfo{}, kes.ErrNotAllowed
			}
			return config.Vault.GetEnclaveInfo(r.Context(), name)
		})
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Response{
			Name:      info.Name,
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

func deleteEnclave(config *RouterConfig) API {
	const (
		Method  = http.MethodDelete
		APIPath = "/v1/enclave/delete/"
		MaxBody = 0
		Timeout = 15 * time.Second
		Verify  = true
	)
	var handler HandlerFunc = func(w http.ResponseWriter, r *http.Request) error {
		name, err := nameFromRequest(r, APIPath)
		if err != nil {
			return err
		}

		if err = Sync(config.Vault.Locker(), func() error {
			sysAdmin, err := config.Vault.Admin(r.Context())
			if err != nil {
				return err
			}
			if identity := auth.Identify(r); identity != sysAdmin {
				return kes.ErrNotAllowed
			}
			return config.Vault.DeleteEnclave(r.Context(), name)
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
