// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/minio/kes/internal/audit"
	"github.com/minio/kes/internal/sys"
)

func version(config *RouterConfig) API {
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
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
			Commit:  sys.BinaryInfo().CommitID,
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

func edgeVersion(config *EdgeRouterConfig) API {
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
	var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Response{
			Version: sys.BinaryInfo().Version,
			Commit:  sys.BinaryInfo().CommitID,
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
