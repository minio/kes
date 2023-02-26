// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/sys"
)

func status(config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/status"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Version string        `json:"version"`
		OS      string        `json:"os"`
		Arch    string        `json:"arch"`
		UpTime  time.Duration `json:"uptime"`

		CPUs       int    `json:"num_cpu"`
		UsableCPUs int    `json:"num_cpu_used"`
		HeapAlloc  uint64 `json:"mem_heap_used"`
		StackAlloc uint64 `json:"mem_stack_used"`
	}
	startTime := time.Now().UTC()
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				return enclave.VerifyRequest(r)
			})
		}); err != nil {
			Fail(w, err)
			return
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			UpTime:  time.Since(startTime).Round(time.Second),

			CPUs:       runtime.NumCPU(),
			UsableCPUs: runtime.GOMAXPROCS(0),
			HeapAlloc:  memStats.HeapAlloc,
			StackAlloc: memStats.StackSys,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func listAPI(router *Router, config *RouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/api"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		MaxBody int64  `json:"max_body"`
		Timeout int64  `json:"timeout"` // Timeout in seconds
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := Sync(config.Vault.RLocker(), func() error {
			enclave, err := enclaveFromRequest(config.Vault, r)
			if err != nil {
				return err
			}
			return Sync(enclave.RLocker(), func() error {
				return enclave.VerifyRequest(r)
			})
		}); err != nil {
			Fail(w, err)
			return
		}

		apis := router.API()
		responses := make([]Response, 0, len(apis))
		for _, api := range apis {
			responses = append(responses, Response{
				Method:  api.Method,
				Path:    api.Path,
				MaxBody: api.MaxBody,
				Timeout: int64(api.Timeout.Truncate(time.Second).Seconds()),
			})
		}

		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responses)
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func edgeStatus(config *EdgeRouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/status"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Version string        `json:"version"`
		OS      string        `json:"os"`
		Arch    string        `json:"arch"`
		UpTime  time.Duration `json:"uptime"`

		CPUs       int    `json:"num_cpu"`
		UsableCPUs int    `json:"num_cpu_used"`
		HeapAlloc  uint64 `json:"mem_heap_used"`
		StackAlloc uint64 `json:"mem_stack_used"`
	}
	startTime := time.Now().UTC()
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Fail(w, err)
			return
		}

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			UpTime:  time.Since(startTime).Round(time.Second),

			CPUs:       runtime.NumCPU(),
			UsableCPUs: runtime.GOMAXPROCS(0),
			HeapAlloc:  memStats.HeapAlloc,
			StackAlloc: memStats.StackSys,
		})
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}

func edgeListAPI(router *Router, config *EdgeRouterConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/api"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		MaxBody int64  `json:"max_body"`
		Timeout int64  `json:"timeout"` // Timeout in seconds
	}
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		if err := auth.VerifyRequest(r, config.Policies, config.Identities); err != nil {
			Fail(w, err)
			return
		}

		apis := router.API()
		responses := make([]Response, 0, len(apis))
		for _, api := range apis {
			responses = append(responses, Response{
				Method:  api.Method,
				Path:    api.Path,
				MaxBody: api.MaxBody,
				Timeout: int64(api.Timeout.Truncate(time.Second).Seconds()),
			})
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responses)
	}
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
		Handler: config.Metrics.Count(config.Metrics.Latency(audit.Log(config.AuditLog, handler))),
	}
}
