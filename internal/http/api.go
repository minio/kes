// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/sys"
)

var errMethodNotAllowed = kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The URI API path.
	MaxBody int64         // The max. body size the API accepts
	Timeout time.Duration // The duration after which an API request times out.
}

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

func lookupEnclave(vault *sys.Vault, req *http.Request) (*sys.Enclave, error) {
	name := req.URL.Query().Get("enclave")
	if name == "" {
		name = sys.DefaultEnclaveName
	}
	if err := validateName(name); err != nil {
		return nil, err
	}
	return vault.GetEnclave(req.Context(), name)
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
