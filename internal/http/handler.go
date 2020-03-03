// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/secret"
	"github.com/secure-io/sio-go/sioutil"
)

func RequireMethod(method string, f http.HandlerFunc) http.HandlerFunc {
	var ErrMethodNotAllowed = kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))

	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Accept", method)
			Error(w, ErrMethodNotAllowed)
			return
		}
		f(w, r)
	}
}

// ValidatePath returns an handler function that verifies that the
// request URL.Path matches apiPattern before calling f. If the
// path does not match the apiPattern it returns the bad request status
// code (400) to the client.
//
// ValidatePath uses the standard library path glob matching for pattern
// matching.
func ValidatePath(apiPattern string, f http.HandlerFunc) http.HandlerFunc {
	var ErrPatternMismatch = kes.NewError(http.StatusBadRequest, fmt.Sprintf("request URL path does not match API pattern: %s", apiPattern))

	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, `/`) {
			r.URL.Path = `/` + r.URL.Path // URL.Path may omit leading slash
		}

		if ok, err := path.Match(apiPattern, r.URL.Path); !ok || err != nil {
			Error(w, ErrPatternMismatch)
			return
		}
		f(w, r)
	}
}

func LimitRequestBody(n int64, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		f(w, r)
	}
}

func EnforcePolicies(roles *auth.Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := roles.Verify(r); err != nil {
			Error(w, err)
			return
		}
		f(w, r)
	}
}

// AuditLog returns a handler function that wraps f and logs the
// HTTP request and response before sending the response status code
// back to the client.
func AuditLog(logger *log.Logger, roles *auth.Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w = &xlog.AuditResponseWriter{
			ResponseWriter: w,
			URL:            *r.URL,
			Identity:       auth.Identify(r, roles.Identify),
			RequestHeader:  r.Header.Clone(),
			Time:           time.Now(),

			Logger: logger,
		}
		f(w, r)
	}
}

// HandleVersion returns a handler function that returns the
// given version as JSON. In particular, it returns a JSON
// object:
//  {
//    "version": "<version>"
//  }
func HandleVersion(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"version":"%s"}`, version) }
}

// HandleCreateKey returns a handler function that generates a new
// random Secret and stores in the Store under the request name, if
// it doesn't exist.
//
// It infers the name of the new Secret from the request URL - in
// particular from the URL's path base.
// See: https://golang.org/pkg/path/#Base
func HandleCreateKey(store *secret.Store) http.HandlerFunc {
	var ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}

		var secret secret.Secret
		bytes, err := sioutil.Random(len(secret))
		if err != nil {
			Error(w, err)
			return
		}
		copy(secret[:], bytes)

		if err := store.Create(name, secret); err != nil {
			Error(w, err)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// HandleImportKey returns a handler function that reads a secret
// value from the request body and stores in the Store under the
// request name, if it doesn't exist.
//
// It infers the name of the new Secret from the request URL - in
// particular from the URL's path base.
// See: https://golang.org/pkg/path/#Base
func HandleImportKey(store *secret.Store) http.HandlerFunc {
	var (
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKey     = kes.NewError(http.StatusBadRequest, "invalid key")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		type request struct {
			Bytes []byte `json:"bytes"`
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}

		var secret secret.Secret
		if len(req.Bytes) != len(secret) {
			Error(w, ErrInvalidKey)
			return
		}
		copy(secret[:], req.Bytes)

		if err := store.Create(name, secret); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleDeleteKey(store *secret.Store) http.HandlerFunc {
	var ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		if err := store.Delete(name); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleGenerateKey(store *secret.Store) http.HandlerFunc {
	var (
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Context []byte `json:"context"`
		}
		type Response struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext []byte `json:"ciphertext"`
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			Error(w, err)
			return
		}

		dataKey, err := sioutil.Random(32)
		if err != nil {
			Error(w, err)
			return
		}
		ciphertext, err := secret.Wrap(dataKey, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
	}
}

func HandleDecryptKey(store *secret.Store) http.HandlerFunc {
	var (
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		type Request struct {
			Ciphertext []byte `json:"ciphertext"`
			Context    []byte `json:"context"`
		}
		type Response struct {
			Plaintext []byte `json:"plaintext"`
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			Error(w, err)
			return
		}
		plaintext, err := secret.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
		})
	}
}

func HandleWritePolicy(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrInvalidPolicyName = kes.NewError(http.StatusBadRequest, "invalid policy name")
		ErrInvalidJSON       = kes.NewError(http.StatusBadRequest, "invalid json")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}

		var policy kes.Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}
		roles.Set(name, &policy)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleReadPolicy(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrInvalidPolicyName = kes.NewError(http.StatusBadRequest, "invalid policy name")
		ErrPolicyNotFound    = kes.NewError(http.StatusBadRequest, "policy does not exist")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}

		policy, ok := roles.Get(name)
		if !ok {
			Error(w, ErrPolicyNotFound)
			return
		}
		json.NewEncoder(w).Encode(policy)
	}
}

func HandleListPolicies(roles *auth.Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var policies = []string{}
		pattern := pathBase(r.URL.Path)
		for _, policy := range roles.Policies() {
			if ok, err := path.Match(pattern, policy); ok && err == nil {
				policies = append(policies, policy)
			}
		}
		json.NewEncoder(w).Encode(policies)
	}
}

func HandleDeletePolicy(roles *auth.Roles) http.HandlerFunc {
	var ErrInvalidPolicyName = kes.NewError(http.StatusBadRequest, "invalid policy name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}
		roles.Delete(name)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleAssignIdentity(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrIdentityUnknown = kes.NewError(http.StatusBadRequest, "identity is unknown")
		ErrIdentityRoot    = kes.NewError(http.StatusBadRequest, "identity is root")
		ErrSelfAssign      = kes.NewError(http.StatusForbidden, "identity cannot assign policy to itself")
		ErrPolicyNotFound  = kes.NewError(http.StatusBadRequest, "policy does not exist")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		identity := kes.Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			Error(w, ErrIdentityUnknown)
			return
		}
		if identity == roles.Root {
			Error(w, ErrIdentityRoot)
			return
		}
		if identity == auth.Identify(r, roles.Identify) {
			Error(w, ErrSelfAssign)
			return
		}

		policy := pathBase(strings.TrimSuffix(r.URL.Path, identity.String()))
		if err := roles.Assign(policy, identity); err != nil {
			Error(w, ErrPolicyNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleListIdentities(roles *auth.Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pattern := pathBase(r.URL.Path)
		identities := map[kes.Identity]string{}
		for id, policy := range roles.Identities() {
			if ok, err := path.Match(pattern, id.String()); ok && err == nil {
				identities[id] = policy
			}
		}
		json.NewEncoder(w).Encode(identities)
	}
}

func HandleForgetIdentity(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrIdentityUnknown = kes.NewError(http.StatusBadRequest, "identity is unknown")
		ErrIdentityRoot    = kes.NewError(http.StatusBadRequest, "identity is root")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		identity := kes.Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			Error(w, ErrIdentityUnknown)
			return
		}
		if identity == roles.Root {
			Error(w, ErrIdentityRoot)
			return
		}
		roles.Forget(identity)
		w.WriteHeader(http.StatusOK)
	}
}

// HandleTraceAuditLog returns a HTTP handler that
// writes whatever log logs to the client.
//
// The returned handler is a long-running server task
// that will wait for the client to close the connection
// resp. until the request context is done.
// Therefore, it will not work properly with (write) timeouts.
func HandleTraceAuditLog(log *xlog.SystemLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := xlog.NewFlushWriter(w)
		log.AddOutput(out)
		defer log.RemoveOutput(out)

		// TODO(aead): set appropriate content-type.
		// For audit logs we could either set "application/x-ndjson"
		// or "application/octet-stream". However, for error logs
		// "application/x-ndjson" would be incorrect unless/until we
		// implement JSON error logging.
		w.WriteHeader(http.StatusOK)

		<-r.Context().Done() // Wait for the client to close the connection
	}
}

func pathBase(p string) string { return path.Base(p) }
