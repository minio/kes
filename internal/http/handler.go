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
	"github.com/minio/kes/internal/sys"
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
	ErrMethodNotAllowed := kes.NewError(http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))

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
	ErrPatternMismatch := kes.NewError(http.StatusBadRequest, fmt.Sprintf("request URL path does not match API pattern: %s", apiPattern))

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
func enforcePolicies(config *ServerConfig, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.VerifyRequest(r); err != nil {
			Error(w, err)
			return
		}
		f(w, r)
	}
}

// audit returns a handler function that wraps f and logs the
// HTTP request and response before sending the response status code
// back to the client.
func audit(logger *log.Logger, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w = &AuditResponseWriter{
			ResponseWriter: w,
			Logger:         logger,

			URL:      *r.URL,
			Identity: auth.Identify(r),
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
func handleStatus(config *ServerConfig) http.HandlerFunc {
	type Status struct {
		Version string        `json:"version"`
		UpTime  time.Duration `json:"uptime"`

		KMS struct {
			State   string        `json:"state,omitempty"`
			Latency time.Duration `json:"latency,omitempty"`
		} `json:"kms"`
	}
	startTime := time.Now()
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		kmsState, err := enclave.Status(r.Context())
		if err != nil {
			kmsState = key.StoreState{
				State: key.StoreUnreachable,
			}
			config.ErrorLog.Log().Printf("http: failed to connect to key store: %v", err)
		}

		status := Status{
			Version: config.Version,
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
func handleCreateKey(config *ServerConfig) http.HandlerFunc {
	ErrInvalidKeyName := kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}

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

		if err := enclave.CreateKey(r.Context(), name, key.New(bytes)); err != nil {
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
func handleImportKey(config *ServerConfig) http.HandlerFunc {
	var (
		ErrInvalidKeyName = kes.NewError(http.StatusBadRequest, "invalid key name")
		ErrInvalidJSON    = kes.NewError(http.StatusBadRequest, "invalid json")
		ErrInvalidKey     = kes.NewError(http.StatusBadRequest, "invalid key")
	)
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}

		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}

		if len(req.Bytes) != key.Size {
			Error(w, ErrInvalidKey)
			return
		}

		if err := enclave.CreateKey(r.Context(), name, key.New(req.Bytes)); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleDeleteKey(config *ServerConfig) http.HandlerFunc {
	ErrInvalidKeyName := kes.NewError(http.StatusBadRequest, "invalid key name")

	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		if err := enclave.DeleteKey(r.Context(), name); err != nil {
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
func handleGenerateKey(config *ServerConfig) http.HandlerFunc {
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
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
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
		secret, err := enclave.GetKey(r.Context(), name)
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
func handleEncryptKey(config *ServerConfig) http.HandlerFunc {
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

		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		secret, err := enclave.GetKey(r.Context(), name)
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
func handleDecryptKey(config *ServerConfig) http.HandlerFunc {
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

		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidKeyName)
			return
		}
		secret, err := enclave.GetKey(r.Context(), name)
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
func handleListKeys(config *ServerConfig) http.HandlerFunc {
	type Response struct {
		Name string
	}
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		iterator, err := enclave.ListKeys(r.Context())
		if err != nil {
			Error(w, err)
			return
		}
		w.Header().Set("Trailer", "Status,Error")

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

func handleWritePolicy(config *ServerConfig) http.HandlerFunc {
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
		var policy auth.Policy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			Error(w, ErrInvalidJSON)
			return
		}

		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.SetPolicy(r.Context(), name, &policy); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleReadPolicy(config *ServerConfig) http.HandlerFunc {
	ErrInvalidPolicyName := kes.NewError(http.StatusBadRequest, "invalid policy name")
	type Response struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}

		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		policy, err := enclave.GetPolicy(r.Context(), name)
		if err != nil {
			Error(w, err)
			return
		}
		json.NewEncoder(w).Encode(&Response{
			Allow: policy.Allow,
			Deny:  policy.Deny,
		})
	}
}

func handleListPolicies(config *ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		iterator, err := enclave.ListPolicies(r.Context())
		if err != nil {
			Error(w, err)
			return
		}

		var policies []string
		pattern := pathBase(r.URL.Path)
		for iterator.Next() {
			if ok, err := path.Match(pattern, iterator.Name()); ok && err == nil {
				policies = append(policies, iterator.Name())
			}
		}
		json.NewEncoder(w).Encode(policies)
	}
}

func handleDeletePolicy(config *ServerConfig) http.HandlerFunc {
	ErrInvalidPolicyName := kes.NewError(http.StatusBadRequest, "invalid policy name")

	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}

		name := pathBase(r.URL.Path)
		if name == "" {
			Error(w, ErrInvalidPolicyName)
			return
		}
		if err = enclave.DeleteKey(r.Context(), name); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleAssignIdentity(config *ServerConfig) http.HandlerFunc {
	var (
		ErrIdentityUnknown = kes.NewError(http.StatusBadRequest, "identity is unknown")
		ErrSelfAssign      = kes.NewError(http.StatusForbidden, "identity cannot assign policy to itself")
	)
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}

		identity := kes.Identity(pathBase(r.URL.Path))
		if identity.IsUnknown() {
			Error(w, ErrIdentityUnknown)
			return
		}
		if self := auth.Identify(r); self == identity {
			Error(w, ErrSelfAssign)
			return
		}

		policy := pathBase(strings.TrimSuffix(r.URL.Path, identity.String()))
		if err = enclave.AssignIdentity(r.Context(), policy, identity); err != nil {
			Error(w, err)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func handleListIdentities(config *ServerConfig) http.HandlerFunc {
	type Response struct {
		Identity kes.Identity `json:"identity"`
		Policy   string       `json:"policy"`
	}

	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		iterator, err := enclave.ListIdentities(r.Context())
		if err != nil {
			Error(w, err)
			return
		}

		w.Header().Set("Trailer", "Status,Error")
		var (
			pattern    = pathBase(r.URL.Path)
			encoder    = json.NewEncoder(w)
			hasWritten bool
		)
		w.Header().Set("Content-Type", "application/x-ndjson")
		for iterator.Next() {
			if ok, err := path.Match(pattern, iterator.Identity().String()); ok && err == nil {
				info, err := enclave.GetIdentity(r.Context(), iterator.Identity())
				if err != nil {
					if !hasWritten {
						Error(w, err)
					} else {
						ErrorTrailer(w, err)
					}
					return
				}

				hasWritten = true
				err = encoder.Encode(Response{
					Identity: iterator.Identity(),
					Policy:   info.Policy,
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

func handleForgetIdentity(config *ServerConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		enclave, err := getEnclave(config.Vault, r)
		if err != nil {
			Error(w, err)
			return
		}
		if err = enclave.DeleteIdentity(r.Context(), kes.Identity(pathBase(r.URL.Path))); err != nil {
			Error(w, err)
			return
		}
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

func getEnclave(vault sys.Vault, r *http.Request) (*sys.Enclave, error) {
	return vault.GetEnclave(r.Context(), r.URL.Query().Get("enclave"))
}
