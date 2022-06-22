package http

import (
	"encoding/json"
	"net/http"
	"runtime"
	"time"

	"github.com/minio/kes/internal/sys"
	"github.com/prometheus/common/expfmt"
)

func version(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method  = http.MethodGet
		APIPath = "/version"
		MaxBody = 0
		Timeout = 15 * time.Second
	)
	type Response struct {
		Version string `json:"version"`
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w = audit(w, r, config.AuditLog.Log())
		if r.Method != Method {
			w.Header().Set("Accept", Method)
			Error(w, errMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
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

func status(mux *http.ServeMux, config *ServerConfig) API {
	const (
		Method      = http.MethodGet
		APIPath     = "/v1/status"
		MaxBody     = 0
		Timeout     = 15 * time.Second
		ContentType = "application/json"
	)
	type Response struct {
		Version string        `json:"version"`
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

		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		w.Header().Set("Content-Type", ContentType)
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
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

func metrics(mux *http.ServeMux, config *ServerConfig) API {
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

func listAPIs(mux *http.ServeMux, config *ServerConfig) API {
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
