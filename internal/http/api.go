// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
)

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The URI API path.
	MaxBody int64         // The max. body size the API accepts
	Timeout time.Duration // The duration after which an API request times out.
}

// A ServerConfig structure is used to configure a
// KES server.
type ServerConfig struct {
	// Certificate is TLS server certificate.
	Certificate *Certificate

	Vault sys.Vault

	// Proxy is an optional TLS proxy that sits
	// in-front of this server and forwards client
	// requests.
	//
	// A TLS proxy is responsible for forwarding
	// the client certificates via a request
	// header such that this server can apply
	// the corresponding policy.
	Proxy *auth.TLSProxy

	// AuditLog is a log target that receives
	// audit log events.
	AuditLog *xlog.Target

	// ErrorLog is a log target that receives
	// error log events.
	ErrorLog *xlog.Target

	// Metrics gathers various informations about
	// the server.
	Metrics *metric.Metrics

	APIs []API
}

// NewServerMux returns a new KES server handler that
// uses the given ServerConfig to implement the KES
// HTTP API.
func NewServerMux(config *ServerConfig) *http.ServeMux {
	mux := http.NewServeMux()
	config.APIs = append(config.APIs, version(mux, config))
	config.APIs = append(config.APIs, status(mux, config))
	config.APIs = append(config.APIs, metrics(mux, config))
	config.APIs = append(config.APIs, listAPIs(mux, config))

	config.APIs = append(config.APIs, createKey(mux, config))
	config.APIs = append(config.APIs, importKey(mux, config))
	config.APIs = append(config.APIs, deleteKey(mux, config))
	config.APIs = append(config.APIs, generateKey(mux, config))
	config.APIs = append(config.APIs, encryptKey(mux, config))
	config.APIs = append(config.APIs, decryptKey(mux, config))
	config.APIs = append(config.APIs, bulkDecryptKey(mux, config))
	config.APIs = append(config.APIs, listKey(mux, config))

	config.APIs = append(config.APIs, describePolicy(mux, config))
	config.APIs = append(config.APIs, assignPolicy(mux, config))
	config.APIs = append(config.APIs, readPolicy(mux, config))
	config.APIs = append(config.APIs, writePolicy(mux, config))
	config.APIs = append(config.APIs, listPolicy(mux, config))
	config.APIs = append(config.APIs, deletePolicy(mux, config))

	config.APIs = append(config.APIs, describeIdentity(mux, config))
	config.APIs = append(config.APIs, selfDescribeIdentity(mux, config))
	config.APIs = append(config.APIs, listIdentity(mux, config))
	config.APIs = append(config.APIs, deleteIdentity(mux, config))

	config.APIs = append(config.APIs, logErrorEvents(mux, config))
	config.APIs = append(config.APIs, logAuditEvents(mux, config))

	config.APIs = append(config.APIs, createEnclave(mux, config))
	config.APIs = append(config.APIs, deleteEnclave(mux, config))

	config.APIs = append(config.APIs, sealVault(mux, config))

	mux.HandleFunc("/", timeout(10*time.Second, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}))
	return mux
}

var errMethodNotAllowed = kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))

// audit returns an http.ResponseWriter that wraps w
// and logs an audit event containing some request
// details right before w sends a response to the client.
func audit(w http.ResponseWriter, r *http.Request, logger *log.Logger) http.ResponseWriter {
	aw := &AuditResponseWriter{
		ResponseWriter: w,
		Logger:         logger,

		URL:       *r.URL,
		Identity:  auth.Identify(r),
		CreatedAt: time.Now(),
	}
	if ip := auth.ForwardedIPFromContext(r.Context()); ip != nil {
		aw.IP = ip
	} else if addr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		aw.IP = net.ParseIP(addr)
	}
	return aw
}

func proxy(proxy *auth.TLSProxy, f http.HandlerFunc) http.HandlerFunc {
	if proxy == nil {
		return f
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if err := proxy.Verify(r); err != nil {
			Error(w, err)
			return
		}
		f(w, r)
	}
}

func lookupEnclave(vault sys.Vault, req *http.Request) (*sys.Enclave, error) {
	return vault.GetEnclave(req.Context(), req.URL.Query().Get("enclave"))
}

// validateName checks whether name is a valid
// KES HTTP API argument. For example a valid
// key or policy name.
func validateName(name string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	const ( // Valid characters are: { 0-9 , A-Z , a-z , - , _ }
		ASCIINumberStart    = 0x30
		ASCIINumberEnd      = 0x39
		ASCIIUpperCaseStart = 0x41
		ASCIIUpperCaseEnd   = 0x5a
		ASCIILowerCaseStart = 0x61
		ASCIILowerCaseEnd   = 0x7a

		ASCIIHyphen     = 0x2d
		ASCIIUnderscore = 0x5f
	)
	if name == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is empty")
	}
	if len(name) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is too long")
	}
	for _, r := range name {
		switch {
		case r >= ASCIINumberStart && r <= ASCIINumberEnd:
		case r >= ASCIIUpperCaseStart && r <= ASCIIUpperCaseEnd:
		case r >= ASCIILowerCaseStart && r <= ASCIILowerCaseEnd:
		case r == ASCIIHyphen:
		case r == ASCIIUnderscore:
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: name contains invalid character")
		}
	}
	return nil
}

// validatePattern checks whether pattern is a valid
// KES HTTP API argument pattern. For example a valid
// key or policy pattern for listing.
func validatePattern(pattern string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	const ( // Valid characters are: { 0-9 , A-Z , a-z , - , _ }
		ASCIINumberStart    = 0x30
		ASCIINumberEnd      = 0x39
		ASCIIUpperCaseStart = 0x41
		ASCIIUpperCaseEnd   = 0x5a
		ASCIILowerCaseStart = 0x61
		ASCIILowerCaseEnd   = 0x7a

		ASCIIHyphen     rune = '-'
		ASCIIUnderscore rune = '_'
		ASCIIStar       rune = '*'
	)
	if pattern == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is empty")
	}
	if len(pattern) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is too long")
	}
	for _, r := range pattern {
		switch {
		case r >= ASCIINumberStart && r <= ASCIINumberEnd:
		case r >= ASCIIUpperCaseStart && r <= ASCIIUpperCaseEnd:
		case r >= ASCIILowerCaseStart && r <= ASCIILowerCaseEnd:
		case r == ASCIIHyphen:
		case r == ASCIIUnderscore:
		case r == ASCIIStar:
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: pattern contains invalid character")
		}
	}
	return nil
}

// normalizeURL normalizes the given URL by adding a
// '/' to its path, if not present.
//
// It returns an error if the config.APIsPath is not an URL path
// prefix.
func normalizeURL(url *url.URL, apiPath string) error {
	if !strings.HasPrefix(url.Path, "/") {
		url.Path = "/" + url.Path
	}
	if !strings.HasPrefix(url.Path, apiPath) {
		return errors.New("invalid API path")
	}
	return nil
}
