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

	"github.com/secure-io/sio-go/sioutil"
)

func RequireMethod(method string, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Accept", method)
			w.WriteHeader(http.StatusMethodNotAllowed)
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
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, `/`) {
			r.URL.Path = `/` + r.URL.Path // URL.Path may omit leading slash
		}

		if ok, err := path.Match(apiPattern, r.URL.Path); !ok || err != nil {
			http.Error(w, fmt.Sprintf("request URL path does not match API pattern: %s", apiPattern), http.StatusBadRequest)
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
			http.Error(w, err.Error(), statusCode(err))
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
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		copy(secret[:], bytes)

		if err := store.Create(name, secret); err != nil {
			http.Error(w, err.Error(), statusCode(err))
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
	return func(w http.ResponseWriter, r *http.Request) {
		type request struct {
			Bytes []byte `json:"bytes"`
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		var secret Secret
		if len(req.Bytes) != len(secret) {
			http.Error(w, "invalid key", http.StatusBadRequest)
			return
		}
		copy(secret[:], req.Bytes)

		if err := store.Create(name, secret); err != nil {
			http.Error(w, err.Error(), statusCode(err))
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleDeleteKey(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		if err := store.Delete(name); err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func HandleGenerateKey(store Store) http.HandlerFunc {
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
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			err = asStatusError(err, ErrKeyNotFound.Error(), ErrKeyNotFound.Status())
			http.Error(w, err.Error(), statusCode(err))
			return
		}

		dataKey, err := sioutil.Random(32)
		if err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		ciphertext, err := secret.Wrap(dataKey, req.Context)
		if err != nil {
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext:  dataKey,
			Ciphertext: ciphertext,
		})
	}
}

func HandleDecryptKey(store Store) http.HandlerFunc {
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
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid key name", http.StatusBadRequest)
			return
		}
		secret, err := store.Get(name)
		if err != nil {
			err = asStatusError(err, ErrKeyNotFound.Error(), ErrKeyNotFound.Status())
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		plaintext, err := secret.Unwrap(req.Ciphertext, req.Context)
		if err != nil {
			err = asStatusError(err, "not authentic", http.StatusBadRequest)
			http.Error(w, err.Error(), statusCode(err))
			return
		}
		json.NewEncoder(w).Encode(Response{
			Plaintext: plaintext,
		})
	}
}

func HandleWritePolicy(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}

		var policy Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		roles.Set(name, &policy)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleReadPolicy(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}

		policy, ok := roles.Get(name)
		if !ok {
			http.Error(w, "policy does not exists", http.StatusNotFound)
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
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			http.Error(w, "invalid policy name", http.StatusBadRequest)
			return
		}
		roles.Delete(name)
		w.WriteHeader(http.StatusOK)
	}
}

func HandleAssignIdentity(roles *Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			http.Error(w, "invalid identity", http.StatusBadRequest)
			return
		}
		if identity == roles.Root {
			http.Error(w, "identity is root", http.StatusBadRequest)
			return
		}
		if identity == Identify(r, roles.Identify) {
			http.Error(w, "invalid identity: you cannot assign a policy to yourself", http.StatusBadRequest)
			return
		}

		policy := pathBase(strings.TrimSuffix(r.URL.Path, identity.String()))
		if err := roles.Assign(policy, identity); err != nil {
			http.Error(w, "policy does not exists", http.StatusNotFound)
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
	return func(w http.ResponseWriter, r *http.Request) {
		identity := Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			http.Error(w, "invalid identity", http.StatusBadRequest)
			return
		}
		if identity == roles.Root {
			http.Error(w, "identity is root", http.StatusBadRequest)
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

func statusCode(err error) int {
	if err, ok := err.(interface{ Status() int }); ok {
		return err.Status()
	}
	return http.StatusInternalServerError
}

func asStatusError(err error, msg string, status int) error {
	if _, ok := err.(interface{ Status() int }); ok {
		return err
	}
	return NewError(status, fmt.Sprintf("%s: %s", msg, err.Error()))
}
