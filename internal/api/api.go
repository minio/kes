// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/kes-go"
)

// API paths exposed by KES clusters and KES edge servers.
// Some APIs are only exposed by KES clusters, not
// edge servers.
const (
	PathVersion  = "/version"
	PathStatus   = "/v1/status"
	PathReady    = "/v1/ready"
	PathMetrics  = "/v1/metrics"
	PathListAPIs = "/v1/api"

	PathEnclaveCreate   = "/v1/enclave/create/"   // cluster only
	PathEnclaveDescribe = "/v1/enclave/describe/" // cluster only
	PathEnclaveDelete   = "/v1/enclave/delete/"   // cluster only
	PathEnclaveList     = "/v1/enclave/list/"     // cluster only

	PathSecretKeyCreate   = "/v1/key/create/"
	PathSecretKeyImport   = "/v1/key/import/"
	PathSecretKeyDescribe = "/v1/key/describe/"
	PathSecretKeyDelete   = "/v1/key/delete/"
	PathSecretKeyList     = "/v1/key/list/"
	PathSecretKeyGenerate = "/v1/key/generate/"
	PathSecretKeyEncrypt  = "/v1/key/encrypt/"
	PathSecretKeyDecrypt  = "/v1/key/decrypt/"

	PathSecretCreate   = "/v1/secret/create/"   // cluster only
	PathSecretDescribe = "/v1/secret/describe/" // cluster only
	PathSecretRead     = "/v1/secret/read/"     // cluster only
	PathSecretDelete   = "/v1/secret/delete/"   // cluster only
	PathSecretList     = "/v1/secret/list"      // cluster only

	PathPolicyCreate   = "/v1/policy/create/" // cluster only
	PathPolicyAssign   = "/v1/policy/assign/" // cluster only
	PathPolicyDescribe = "/v1/policy/describe/"
	PathPolicyRead     = "/v1/policy/read/"
	PathPolicyDelete   = "/v1/policy/delete/" // cluster only
	PathPolicyList     = "/v1/policy/list/"

	PathIdentityCreate       = "/v1/identity/create/" // cluster only
	PathIdentityDescribe     = "/v1/identity/describe/"
	PathIdentityList         = "/v1/identity/list/"
	PathIdentityDelete       = "/v1/identity/delete/" // cluster only
	PathIdentitySelfDescribe = "/v1/identity/self/describe"

	PathLogError = "/v1/log/error"
	PathLogAudit = "/v1/log/audit"

	PathClusterExpand   = "/v1/cluster/expand"   // cluster only
	PathClusterDescribe = "/v1/cluster/describe" // cluster only
	PathClusterShrink   = "/v1/cluster/shrink"   // cluster only
	PathClusterBackup   = "/v1/cluster/backup"   // cluster only
	PathClusterRestore  = "/v1/cluster/restore"  // cluster only

	PathClusterRPCReplicate = "/v1/cluster/rpc/replicate" // cluster only
	PathClusterRPCForward   = "/v1/cluster/rpc/forward"   // cluster only
	PathClusterRPCVote      = "/v1/cluster/rpc/vote"      // cluster only
)

func Failf(w http.ResponseWriter, code int, format string, a ...any) {
	type Error struct {
		Message string `json:"message"`
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Error{
		Message: fmt.Sprintf(format, a...),
	})
}

func CutPath(url *url.URL, path string, f func(string) error) (string, error) {
	return trimPath(url, path, f)
}

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The URI API path
	MaxBody int64         // The max. body size the API accepts
	Timeout time.Duration // The duration after which an API request times out. 0 means no timeout

	Verify Verifier

	// Handler implements the API.
	//
	// When invoked by the API's ServeHTTP method, the handler
	// can rely upon:
	//  - the request method matching the API's HTTP method.
	//  - the API path being a prefix of the request URL.
	//  - the request body being limited to the API's MaxBody size.
	//  - the request timing out after the duration specified for the API.
	Handler Handler
}

type Verifier interface {
	Verify(*http.Request) (kes.Identity, error)
}

type VerifyFunc func(*http.Request) (kes.Identity, error)

func (f VerifyFunc) Verify(r *http.Request) (kes.Identity, error) { return f(r) }

var InsecureSkipVerify Verifier = VerifyFunc(insecureSkipVerify)

func insecureSkipVerify(*http.Request) (kes.Identity, error) { return "", nil }

type HandlerFunc func(http.ResponseWriter, *http.Request, Verifier)

func (f HandlerFunc) ServeAPI(w http.ResponseWriter, r *http.Request, v Verifier) { f(w, r, v) }

type Handler interface {
	ServeAPI(http.ResponseWriter, *http.Request, Verifier)
}

// ServerHTTP takes an HTTP Request and ResponseWriter and executes the
// API's Handler.
func (a API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Method == http.MethodPut && r.Method == http.MethodPost {
		r.Method = http.MethodPut
	}
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
	a.Handler.ServeAPI(w, r, a.Verify)
}

const (
	maxNameLen   = 128
	maxPrefixLen = 128
)

func trimPath(url *url.URL, path string, f func(string) error) (string, error) {
	s := strings.TrimPrefix(url.Path, path)
	if len(s) == len(url.Path) && path != "" {
		return "", fmt.Errorf("api: invalid path: '%s' is not a prefix of '%s'", path, url.Path)
	}
	if err := f(s); err != nil {
		return "", err
	}
	return s, nil
}

func IsValidPrefix(s string) error { return isValidPrefix(s) }

func isValidPrefix(s string) error {
	if len(s) > maxPrefixLen {
		return kes.NewError(http.StatusBadRequest, "prefix is too long")
	}
	for _, r := range s { // Valid characters are: [ 0-9 , A-Z , a-z , - , _ , * ]
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		case r == '_':
		default:
			return kes.NewError(http.StatusBadRequest, "prefix contains invalid character")
		}
	}
	return nil
}

func IsValidName(s string) error {
	return verifyName(s)
}

func IsValidPattern(s string) error {
	return verifyPattern(s)
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
