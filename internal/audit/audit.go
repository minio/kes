// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package audit

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/log"
)

// Log wraps h with an http.Handler that logs an audit log
// event to the given logger.
func Log(logger *log.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := auth.ForwardedIPFromContext(r.Context())
		if ip == nil {
			if addr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				ip = net.ParseIP(addr)
			}
		}
		identity, _ := auth.IdentifyRequest(r.TLS)
		w = &responseWriter{
			rw: w,

			log:       logger,
			url:       *r.URL,
			ip:        ip,
			identity:  identity,
			timestamp: time.Now(),
		}
		h.ServeHTTP(w, r)
	})
}

type responseWriter struct {
	rw http.ResponseWriter

	log       *log.Logger
	url       url.URL
	ip        net.IP
	identity  kes.Identity
	timestamp time.Time

	hasSendHeaders atomic.Bool
}

func (w *responseWriter) Header() http.Header { return w.rw.Header() }

func (w *responseWriter) Write(p []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return w.rw.Write(p)
}

func (w *responseWriter) WriteHeader(status int) {
	if !w.hasSendHeaders.CompareAndSwap(false, true) {
		return
	}
	w.rw.WriteHeader(status)

	type RequestInfo struct {
		IP       net.IP       `json:"ip,omitempty"`
		Enclave  string       `json:"enclave,omitempty"`
		APIPath  string       `json:"path"`
		Identity kes.Identity `json:"identity,omitempty"`
	}
	type ResponseInfo struct {
		StatusCode int           `json:"code"`
		Time       time.Duration `json:"time"`
	}
	type Response struct {
		Timestamp time.Time    `json:"time"`
		Request   RequestInfo  `json:"request"`
		Response  ResponseInfo `json:"response"`
	}

	json.NewEncoder(w.log.Writer()).Encode(Response{
		Timestamp: w.timestamp,
		Request: RequestInfo{
			IP:       w.ip,
			Enclave:  w.url.Query().Get("enclave"),
			APIPath:  w.url.Path,
			Identity: w.identity,
		},
		Response: ResponseInfo{
			StatusCode: status,
			Time:       time.Now().UTC().Sub(w.timestamp.UTC()).Truncate(1 * time.Microsecond),
		},
	})
}

func (w *responseWriter) Flush() {
	if flusher, ok := w.rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Unwrap returns the underlying http.ResponseWriter.
//
// This method is implemented for http.ResponseController.
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.rw }
