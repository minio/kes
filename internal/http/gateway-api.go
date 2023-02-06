// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
)

func gatewayVersion(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/version"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type Response struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog)
		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
			Commit:  sys.BinaryInfo().CommitID,
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

func gatewayStatus(mux *http.ServeMux, config *GatewayConfig) API {
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
	handler := func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, config.Metrics.Count(config.Metrics.Latency(handler)))))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func gatewayMetrics(mux *http.ServeMux, config *GatewayConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/v1/metrics"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	handler := func(w http.ResponseWriter, r *http.Request) {
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

		contentType := expfmt.Negotiate(r.Header)
		w.Header().Set("Content-Type", string(contentType))
		w.WriteHeader(http.StatusOK)
		config.Metrics.EncodeTo(expfmt.NewEncoder(w, contentType))
	}
	mux.HandleFunc(APIPath, timeout(Timeout, proxy(config.Proxy, handler)))
	return API{
		Method:  Method,
		Path:    APIPath,
		MaxBody: MaxBody,
		Timeout: Timeout,
	}
}

func gatewayListAPIs(mux *http.ServeMux, config *GatewayConfig) API {
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
	handler := func(w http.ResponseWriter, r *http.Request) {
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

		responses := make([]Response, 0, len(config.APIs))
		for _, api := range config.APIs {
			responses = append(responses, Response{
				Method:  api.Method,
				Path:    api.Path,
				MaxBody: api.MaxBody,
				Timeout: int64(api.Timeout.Truncate(time.Second).Seconds()),
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
