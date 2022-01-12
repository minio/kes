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
	"strconv"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/prometheus/common/expfmt"
	"github.com/secure-io/sio-go/sioutil"
)

// requireMethod returns an http.HandlerFunc that checks whether
// the method of a client request matches the expected method before
// calling f.
//
// If the client request method does not match the given method
// it returns an error and http.StatusMethodNotAllowed to the client.
func requireMethod(method string, f http.HandlerFunc) http.HandlerFunc {
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

// validatePath returns an handler function that verifies that the
// request URL.Path matches apiPattern before calling f. If the
// path does not match the apiPattern it returns the bad request status
// code (400) to the client.
//
// validatePath uses the standard library path glob matching for pattern
// matching.
func validatePath(apiPattern string, f http.HandlerFunc) http.HandlerFunc {
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

// limitRequestBody returns an http.HandlerFunc that limits the
// body of incoming requests to n bytes before calling f.
//
// It should be used to limit the amount of data a client can send
// to prevent flooding/DoS attacks.
func limitRequestBody(n int64, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, n)
		f(w, r)
	}
}

// enforcePolicies returns an http.Handler that verifies the
// request using policy/role based identity authentication before
// calling f.
//
// If the request is not authorized it will return an error to the
// client and does not call f.
func enforcePolicies(roles *auth.Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := roles.Verify(r); err != nil {
			Error(w, err)
			return
		}
		f(w, r)
	}
}

// audit returns a handler function that wraps f and logs the
// HTTP request and response before sending the response status code
// back to the client.
func audit(logger *log.Logger, roles *auth.Roles, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w = &AuditResponseWriter{
			ResponseWriter: w,
			Logger:         logger,

			URL:      *r.URL,
			Identity: auth.Identify(r, roles.Identify),
			Time:     time.Now(),
		}
		f(w, r)
	}
}

// handleVersion returns a handler function that returns the
// given version as JSON. In particular, it returns a JSON
// object:
//  {
//    "version": "<version>"
//  }
func handleVersion(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, `{"version":"%s"}`, version) }
}

// handleStatus returns a handler function that returns status
// information, like server version and server up-time, as JSON
// object to the client.
func handleStatus(version string, store key.Store, log *xlog.Target) http.HandlerFunc {
	type Status struct {
		Version string        `json:"version"`
		UpTime  time.Duration `json:"uptime"`

		KMS struct {
			State   string        `json:"state,omitempty"`
			Latency time.Duration `json:"latency,omitempty"`
		} `json:"kms"`
	}
	var startTime = time.Now()
	return func(w http.ResponseWriter, r *http.Request) {
		kmsState, err := store.Status(r.Context())
		if err != nil {
			kmsState = key.StoreState{
				State: key.StoreUnreachable,
			}
			log.Log().Printf("http: failed to connect to key store: %v", err)
		}

		var status = Status{
			Version: version,
			UpTime:  time.Since(startTime).Round(time.Second),
		}
		status.KMS.State = kmsState.State.String()
		status.KMS.Latency = kmsState.Latency.Round(time.Millisecond)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}

// handleCreateKey returns a handler function that generates a new
// random Secret and stores in the Store under the request name, if
// it doesn't exist.
//
// It infers the name of the new Secret from the request URL - in
// particular from the URL's path base.
// See: https://golang.org/pkg/path/#Base
func handleCreateKey(store key.Store) http.HandlerFunc {
	var ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}

		bytes, err := sioutil.Random(key.Size)
		if err != nil {
			Error(w, err)
			return
		}

		if err := store.Create(r.Context(), name, key.New(bytes)); err != nil {
			Error(w, err)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleImportKey returns a handler function that reads a secret
// value from the request body and stores in the Store under the
// request name, if it doesn't exist.
//
// It infers the name of the new Secret from the request URL - in
// particular from the URL's path base.
// See: https://golang.org/pkg/path/#Base
func handleImportKey(store key.Store) http.HandlerFunc {
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

		if len(req.Bytes) != key.Size {
			Error(w, ErrInvalidKey)
			return
		}

		if err := store.Create(r.Context(), name, key.New(req.Bytes)); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleDeleteKey(store key.Store) http.HandlerFunc {
	var ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		if err := store.Delete(r.Context(), name); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handleGenerateKey returns an http.HandlerFunc that generates
// a data encryption key (DEK) at random and returns the plaintext
// and ciphertext version of the DEK to the client. The DEK ciphertext
// is the DEK plaintext encrypted with the secret key from the store.
//
// handleGenerateKey behaves as handleEncryptKey where the plaintext is
// a randomly generated key.
//
// If the client provides an optional context value the
// returned http.HandlerFunc will authenticate but not encrypt
// the context value. The client has to provide the same
// context value again for decryption.
func handleGenerateKey(store key.Store) http.HandlerFunc {
	var (
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
	)
	type Request struct {
		Context []byte `json:"context"` // optional
	}
	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
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
		secret, err := store.Get(r.Context(), name)
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

// handleEncryptKey returns an http.HandlerFunc that encrypts
// and authenticates a plaintext message sent by the client.
//
// It should be used to encrypt small amounts of data - like
// other cryptographic keys or small metadata objects.
// HandleEncryptKey should not be used to encrypt large data
// streams.
//
// If the client provides an optional context value the
// returned http.HandlerFunc will authenticate but not encrypt
// the context value. The client has to provide the same
// context value again for decryption.
func handleEncryptKey(store key.Store) http.HandlerFunc {
	var (
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
	)
	type Request struct {
		Plaintext []byte `json:"plaintext"`
		Context   []byte `json:"context"` // optional
	}
	type Response struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
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
		secret, err := store.Get(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		ciphertext, err := secret.Wrap(req.Plaintext, req.Context)
		if err != nil {
			Error(w, err)
			return
		}
		json.NewEncoder(w).Encode(Response{
			Ciphertext: ciphertext,
		})
	}
}

// handleDecryptKey returns an http.HandlerFunc that decrypts
// and verifies a ciphertext sent by the client produced by
// handleEncryptKey or handleGenerateKey.
//
// If the client has provided a context value during
// encryption / key generation then the client has to provide
// the same context value again.
func handleDecryptKey(store key.Store) http.HandlerFunc {
	var (
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
	)
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"`
	}
	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
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
		secret, err := store.Get(r.Context(), name)
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

// handleListKeys returns an http.HandlerFunc that lists
// all keys stored by the secret.Store that match the
// glob pattern specified by the client.
//
// If an error occurs after a response has been written
// to the client the returned http.HandlerFunc sends an
// HTTP trailer containing this error.
// The client is expected to check for an error trailer
// and only consider the listing complete if it receives
// no such trailer.
func handleListKeys(store key.Store) http.HandlerFunc {
	type Response struct {
		Name string
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Status,Error")

		iterator, err := store.List(r.Context())
		if err != nil {
			Error(w, err)
			return
		}

		var (
			pattern    = pathBase(r.URL.Path)
			encoder    = json.NewEncoder(w)
			hasWritten bool
		)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for iterator.Next() {
			name := iterator.Name()
			if ok, err := path.Match(pattern, name); ok && err == nil {
				hasWritten = true
				err = encoder.Encode(Response{
					Name: name,
				})

				// Once we encounter ErrHandlerTimeout the client connection
				// has time'd out and we can stop sending responses.
				if err == http.ErrHandlerTimeout {
					break
				}

				// If there is another error we be conservative and try to
				// inform the client that something went wrong. However,
				// if we fail to write to the underlying connection there is
				// not really something we can do except stop iterating and
				// not waste server resources.
				if err != nil {
					ErrorTrailer(w, err)
					return
				}
			}
		}
		if err := iterator.Err(); err != nil {
			if !hasWritten {
				Error(w, err)
			} else {
				ErrorTrailer(w, err)
			}
			return
		}

		if !hasWritten {
			w.WriteHeader(http.StatusOK)
		}
		w.Header().Set("Status", strconv.Itoa(http.StatusOK))
		w.Header().Set("Error", "")
	}
}

func handleWritePolicy(roles *auth.Roles) http.HandlerFunc {
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

func handleReadPolicy(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrInvalidPolicyName = kes.NewError(http.StatusBadRequest, "invalid policy name")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}

		policy, ok := roles.Get(name)
		if !ok {
			Error(w, kes.ErrPolicyNotFound)
			return
		}
		json.NewEncoder(w).Encode(policy)
	}
}

func handleListPolicies(roles *auth.Roles) http.HandlerFunc {
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

func handleDeletePolicy(roles *auth.Roles) http.HandlerFunc {
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

func handleAssignIdentity(roles *auth.Roles) http.HandlerFunc {
	var (
		ErrIdentityUnknown = kes.NewError(http.StatusBadRequest, "identity is unknown")
		ErrIdentityRoot    = kes.NewError(http.StatusBadRequest, "identity is root")
		ErrSelfAssign      = kes.NewError(http.StatusForbidden, "identity cannot assign policy to itself")
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
			Error(w, kes.ErrPolicyNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleListIdentities(roles *auth.Roles) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type Response struct {
			Identity kes.Identity `json:"identity"`
			Policy   string       `json:"policy"`
		}
		w.Header().Set("Trailer", "Status,Error")

		var (
			pattern    = pathBase(r.URL.Path)
			encoder    = json.NewEncoder(w)
			hasWritten bool
		)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for identity, policy := range roles.Identities() {
			if ok, err := path.Match(pattern, identity.String()); ok && err == nil {
				hasWritten = true
				err = encoder.Encode(Response{
					Identity: identity,
					Policy:   policy,
				})

				// Once we encounter ErrHandlerTimeout the client connection
				// has time'd out and we can stop sending responses.
				if err == http.ErrHandlerTimeout {
					break
				}

				// If there is another error we be conservative and try to
				// inform the client that something went wrong. However,
				// if we fail to write to the underlying connection there is
				// not really something we can do except stop iterating and
				// not waste server resources.
				if err != nil {
					ErrorTrailer(w, err)
					return
				}
			}
		}

		if !hasWritten {
			w.WriteHeader(http.StatusOK)
		}
		w.Header().Set("Status", strconv.Itoa(http.StatusOK))
		w.Header().Set("Error", "")
	}
}

func handleForgetIdentity(roles *auth.Roles) http.HandlerFunc {
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

// handleTraceAuditLog returns an HTTP handler that adds
// the client as a log target. The client will then receive
// all audit events.
//
// The returned handler is a long-running server task
// that will wait for the client to close the connection
// resp. until the request context is done.
// Therefore, it will not work properly with (write) timeouts.
func handleTraceAuditLog(target *xlog.Target) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := NewFlushWriter(w)
		target.Add(out)
		defer target.Remove(out)

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)

		<-r.Context().Done() // Wait for the client to close the connection
	}
}

// handleTraceErrorLog returns an HTTP handler that adds
// the client as a log target. The client will then receive
// all error events.
//
// The returned handler is a long-running server task
// that will wait for the client to close the connection
// resp. until the request context is done.
// Therefore, it will not work properly with (write) timeouts.
//
// In contrast to handleTraceAuditLog, handleTraceErrorLog
// wraps the http.ResponseWriter such that whatever log logs
// gets converted to the JSON:
//  {
//    "message":"<log-output>",
//  }
func handleTraceErrorLog(target *xlog.Target) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We provide a JSON API. Therefore, our error log
		// must also be converted to JSON / nd-JSON.
		out := xlog.NewErrEncoder(NewFlushWriter(w))
		target.Add(out)
		defer target.Remove(out)

		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)

		<-r.Context().Done() // Wait for the client to close the connection
	}
}

// HandleMetrics returns an HTTP handler that collects all outstanding
// metrics information and writes them to the client.
func handleMetrics(metrics *metric.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We encode the metrics depending upon what encoding
		// formats are accepted/supported by the client.
		contentType := expfmt.Negotiate(r.Header)

		w.Header().Set("Content-Type", string(contentType))
		w.WriteHeader(http.StatusOK)

		metrics.EncodeTo(expfmt.NewEncoder(w, contentType))
	}
}

func pathBase(p string) string { return path.Base(p) }
