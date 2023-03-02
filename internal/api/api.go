// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/sys"
)

// Config is a structure for configuring
// a KES server API.
type Config struct {
	// Timeout is the duration after which a request
	// times out. If Timeout <= 0 the API default
	// is used.
	Timeout time.Duration

	// InsecureSkipAuth controls whether the API verifies
	// client identities. If InsecureSkipAuth is true,
	// the API accepts requests from arbitrary identities.
	// In this mode, the API can be used by anyone who can
	// communicate to the KES server over HTTPS.
	// This should only be set for testing or in certain
	// cases for APIs that don't expose sensitive information,
	// like metrics.
	InsecureSkipAuth bool
}

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The URI API path
	MaxBody int64         // The max. body size the API accepts
	Timeout time.Duration // The duration after which an API request times out. 0 means no timeout
	Verify  bool          // Whether the API verifies the client identity

	// Handler implements the API.
	//
	// When invoked by the API's ServeHTTP method, the handler
	// can rely upon:
	//  - the request method matching the API's HTTP method.
	//  - the API path being a prefix of the request URL.
	//  - the request body being limited to the API's MaxBody size.
	//  - the request timing out after the duration specified for the API.
	Handler http.Handler

	_ [0]int
}

// ServerHTTP takes an HTTP Request and ResponseWriter and executes the
// API's Handler.
func (a API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != a.Method {
		w.Header().Set("Accept", a.Method)
		Fail(w, kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed)))
		return
	}
	if !strings.HasPrefix(r.URL.Path, a.Path) {
		Fail(w, fmt.Errorf("api: patch mismatch: received '%s' - expected '%s'", r.URL.Path, a.Path))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, a.MaxBody)

	if a.Timeout > 0 {
		switch err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(a.Timeout)); {
		case errors.Is(err, http.ErrNotSupported):
			Fail(w, errors.New("internal error: HTTP connection does not accept a timeout"))
			return
		case err != nil:
			Fail(w, fmt.Errorf("internal error: %v", err))
			return
		}
	}
	a.Handler.ServeHTTP(w, r)
}

// nameFromRequest strips the API path from the request URL, verifies
// that the remaining path is a valid name, via verifyName, and returns
// the remaining path.
func nameFromRequest(r *http.Request, apiPath string) (string, error) {
	name := strings.TrimPrefix(r.URL.Path, apiPath)
	if len(name) == len(r.URL.Path) {
		return "", fmt.Errorf("api: patch mismatch: received '%s' - expected '%s'", r.URL.Path, apiPath)
	}
	if err := verifyName(name); err != nil {
		return "", err
	}
	return name, nil
}

// patternFromRequest strips the API path from the request URL, verifies
// that the remaining path is a valid pattern, via verifyPattern, and returns
// the remaining path.
func patternFromRequest(r *http.Request, apiPath string) (string, error) {
	pattern := strings.TrimPrefix(r.URL.Path, apiPath)
	if len(pattern) == len(r.URL.Path) {
		return "", fmt.Errorf("api: patch mismatch: received '%s' - expected '%s'", r.URL.Path, apiPath)
	}
	if err := verifyPattern(pattern); err != nil {
		return "", err
	}
	return pattern, nil
}

// verifyName reports whether the name is valid.
//
// A valid name must only contain numbers (0-9),
// letters (a-z and A-Z) and '-' as well as '_'
// characters.
func verifyName(name string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if name == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is empty")
	}
	if len(name) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: name is too long")
	}
	for _, r := range name { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: name contains invalid character")
		}
	}
	return nil
}

// verifyPattern reports whether the pattern is valid.
//
// A valid pattern must only contain numbers (0-9),
// letters (a-z and A-Z) and '-', '_' as well as '*'
// characters.
func verifyPattern(pattern string) error {
	const MaxLength = 80 // Some arbitrary but reasonable limit

	if pattern == "" {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is empty")
	}
	if len(pattern) > MaxLength {
		return kes.NewError(http.StatusBadRequest, "invalid argument: pattern is too long")
	}
	for _, r := range pattern { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ , * ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		case r == '*':
		default:
			return kes.NewError(http.StatusBadRequest, "invalid argument: pattern contains invalid character")
		}
	}
	return nil
}

// enclaveFromRequest parses the enclave name from the request URL
// and returns the corresponding enclave present at the vault.
func enclaveFromRequest(vault *sys.Vault, req *http.Request) (*sys.Enclave, error) {
	name := req.URL.Query().Get("enclave")
	if name == "" {
		name = sys.DefaultEnclaveName
	}
	if err := verifyName(name); err != nil {
		return nil, err
	}
	return vault.GetEnclave(req.Context(), name)
}

// Sync calls f while holding the given lock and
// releases the lock once f has been finished.
//
// Sync returns the error returned by f, if  any.
func Sync(locker sync.Locker, f func() error) error {
	locker.Lock()
	defer locker.Unlock()

	return f()
}

// VSync calls f while holding the given lock and
// releases the lock once f has been finished.
//
// VSync returns the result of f and its error
// if  any.
func VSync[V any](locker sync.Locker, f func() (V, error)) (V, error) {
	locker.Lock()
	defer locker.Unlock()

	return f()
}
