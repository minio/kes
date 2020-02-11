// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	xerrors "github.com/minio/kes/errors"
	"github.com/secure-io/sio-go/sioutil"
)

func RequireMethod(method string, f http.HandlerFunc) http.HandlerFunc {
	var ErrMethodNotAllowed = xerrors.New(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))

	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Accept", method)
			xerrors.Respond(w, ErrMethodNotAllowed)
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
	var ErrMismatch = xerrors.New(http.StatusBadRequest, fmt.Sprintf("request URL path does not match API pattern: %s", apiPattern))

	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, `/`) {
			r.URL.Path = `/` + r.URL.Path // URL.Path may omit leading slash
		}

		if ok, err := path.Match(apiPattern, r.URL.Path); !ok || err != nil {
			xerrors.Respond(w, ErrMismatch)
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

func EnforcePolicies(roles *Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := roles.enforce(r); err != nil {
			xerrors.Respond(w, err)
			return
		}
		f(w, r)
	}
}

// AuditLog returns a handler function that wraps f and logs the
// HTTP request and response before sending the response status code
// back to the client.
func AuditLog(logger *log.Logger, roles *Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w = &auditResponseWriter{
			ResponseWriter: w,
			URL:            *r.URL,
			Identity:       Identify(r, roles.Identify),
			RequestHeader:  r.Header.Clone(),
			Time:           time.Now(),

			logger: logger,
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
func HandleCreateKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}

		var secret Secret
		bytes, err := sioutil.Random(len(secret))
		if err != nil {
			xerrors.Respond(w, err)
			return
		}
		copy(secret[:], bytes)

		if err := store.Create(name, secret); err != nil {
			xerrors.Respond(w, err)
			return
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
func HandleImportKey(store Store) http.HandlerFunc {
	var (
		ErrInvalidKeyName = xerrors.New(http.StatusBadRequest, "invalid key name")
		ErrInvalidJSON    = xerrors.New(http.StatusBadRequest, "invalid JSON")
		ErrInvalidKey     = xerrors.New(http.StatusBadRequest, "invalid key")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		type request struct {
			Bytes []byte `json:"bytes"`
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidKeyName)
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			xerrors.Respond(w, ErrInvalidJSON)
			return
		}

		var secret Secret
		if len(req.Bytes) != len(secret) {
			xerrors.Respond(w, ErrInvalidKey)
			return
		}
		copy(secret[:], req.Bytes)

		if err := store.Create(name, secret); err != nil {
			xerrors.Respond(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleDeleteKey(store Store) http.HandlerFunc {
	var ErrInvalidKeyName = xerrors.New(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidKeyName)
			return
		}
		if err := store.Delete(name); err != nil {
			xerrors.Respond(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleGenerateKey(store Store) http.HandlerFunc {
	var (
		ErrInvalidKeyName = xerrors.New(http.StatusBadRequest, "invalid key name")
		ErrInvalidJSON    = xerrors.New(http.StatusBadRequest, "invalid JSON")
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
			xerrors.Respond(w, ErrInvalidJSON)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidKeyName)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			if !xerrors.HasStatus(err) {
				err = ErrKeyNotFound
			}
			xerrors.Respond(w, err)
			return
		}

		dataKey, err := sioutil.Random(32)
		if err != nil {
			xerrors.Respond(w, err)
			return
		}
		ciphertext, err := secret.Wrap(dataKey, req.Context)
		if err != nil {
			xerrors.Respond(w, err)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		}) // implicitly writes 200 OK
	}
}

func HandleDecryptKey(store Store) http.HandlerFunc {
	var (
		ErrInvalidKeyName = xerrors.New(http.StatusBadRequest, "invalid key name")
		ErrInvalidJSON    = xerrors.New(http.StatusBadRequest, "invalid JSON")
		ErrNotAuthentic   = xerrors.New(http.StatusBadRequest, "not authentic")
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
			xerrors.Respond(w, ErrInvalidJSON)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidKeyName)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			if !xerrors.HasStatus(err) {
				err = ErrKeyNotFound
			}
			xerrors.Respond(w, err)
			return
		}
		plaintext, err := secret.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			if !xerrors.HasStatus(err) {
				err = ErrNotAuthentic
			}
			xerrors.Respond(w, err)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
		}) // implicitly writes 200 OK
	}
}

func HandleWritePolicy(roles *Roles) http.HandlerFunc {
	var (
		ErrInvalidPolicyName = xerrors.New(http.StatusBadRequest, "invalid policy name")
		ErrInvalidJSON       = xerrors.New(http.StatusBadRequest, "invalid JSON")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidPolicyName)
			return
		}

		var policy Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			xerrors.Respond(w, ErrInvalidJSON)
			return
		}
		roles.Set(name, &policy)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleReadPolicy(roles *Roles) http.HandlerFunc {
	var (
		ErrInvalidPolicyName = xerrors.New(http.StatusBadRequest, "invalid policy name")
		ErrPolicyNotFound    = xerrors.New(http.StatusBadRequest, "policy does not exist")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidPolicyName)
			return
		}

		policy, ok := roles.Get(name)
		if !ok {
			xerrors.Respond(w, ErrPolicyNotFound)
			return
		}
		json.NewEncoder(w).Encode(policy)
	}
}

func HandleListPolicies(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var policies []string
		pattern := pathBase(r.URL.Path)
		for _, policy := range roles.Policies() {
			if ok, err := path.Match(pattern, policy); ok && err == nil {
				policies = append(policies, policy)
			}
		}
		json.NewEncoder(w).Encode(policies)
	}
}

func HandleDeletePolicy(roles *Roles) http.HandlerFunc {
	var ErrInvalidPolicyName = xerrors.New(http.StatusBadRequest, "invalid policy name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			xerrors.Respond(w, ErrInvalidPolicyName)
			return
		}
		roles.Delete(name)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleAssignIdentity(roles *Roles) http.HandlerFunc {
	var (
		ErrInvalidIdenitity = xerrors.New(http.StatusBadRequest, "invalid identity")
		ErrIdentityIsRoot   = xerrors.New(http.StatusBadRequest, "identity is root")
		ErrSelfAssign       = xerrors.New(http.StatusBadRequest, "invalid identity: you cannot assign a policy to yourself")
		ErrPolicyNotFound   = xerrors.New(http.StatusNotFound, "policy does not exist")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			xerrors.Respond(w, ErrInvalidIdenitity)
			return
		}
		if identity == roles.Root {
			xerrors.Respond(w, ErrIdentityIsRoot)
			return
		}
		if identity == Identify(r, roles.Identify) {
			xerrors.Respond(w, ErrSelfAssign)
			return
		}

		policy := pathBase(strings.TrimSuffix(r.URL.Path, identity.String()))
		if err := roles.Assign(policy, identity); err != nil {
			xerrors.Respond(w, ErrPolicyNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleListIdentities(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pattern := pathBase(r.URL.Path)
		identities := map[Identity]string{}
		for id, policy := range roles.Identities() {
			if ok, err := path.Match(pattern, id.String()); ok && err == nil {
				identities[id] = policy
			}
		}
		json.NewEncoder(w).Encode(identities)
	}
}

func HandleForgetIdentity(roles *Roles) http.HandlerFunc {
	var (
		ErrInvalidIdenitity = xerrors.New(http.StatusBadRequest, "invalid identity")
		ErrIdentityIsRoot   = xerrors.New(http.StatusBadRequest, "identity is root")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			xerrors.Respond(w, ErrInvalidIdenitity)
			return
		}
		if identity == roles.Root {
			xerrors.Respond(w, ErrIdentityIsRoot)
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
func HandleTraceAuditLog(log *SystemLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := newFlushWriter(w)
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
