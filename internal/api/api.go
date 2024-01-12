// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/headers"
)

// API paths exposed by KES servers.
const (
	PathVersion  = "/version"
	PathStatus   = "/v1/status"
	PathReady    = "/v1/ready"
	PathMetrics  = "/v1/metrics"
	PathListAPIs = "/v1/api"

	PathKeyCreate   = "/v1/key/create/"
	PathKeyImport   = "/v1/key/import/"
	PathKeyDescribe = "/v1/key/describe/"
	PathKeyDelete   = "/v1/key/delete/"
	PathKeyList     = "/v1/key/list/"
	PathKeyGenerate = "/v1/key/generate/"
	PathKeyEncrypt  = "/v1/key/encrypt/"
	PathKeyDecrypt  = "/v1/key/decrypt/"
	PathKeyHMAC     = "/v1/key/hmac/"

	PathPolicyDescribe = "/v1/policy/describe/"
	PathPolicyRead     = "/v1/policy/read/"
	PathPolicyList     = "/v1/policy/list/"

	PathIdentityDescribe     = "/v1/identity/describe/"
	PathIdentityList         = "/v1/identity/list/"
	PathIdentitySelfDescribe = "/v1/identity/self/describe"

	PathLogError = "/v1/log/error"
	PathLogAudit = "/v1/log/audit"
)

// Route represents an API route handling a client request.
type Route struct {
	Method  string        // The HTTP method (GET, PUT, DELETE, ...)
	Path    string        // The API Path
	MaxBody mem.Size      // The max. size of a request body
	Timeout time.Duration // Timeout after which the request gets aborted
	Auth    Authenticator // The authentication method for this API route
	Handler Handler       // The API handler implementing the server-side logic
}

// ServeHTTP implements the http.Handler for Route and handles an incoming
// client request as following:
//   - Verify that the request method matches Route.Method.
//   - Verify that the request got routed correctly, i.e. Route.Path is a
//     prefix of the request path.
//   - Limit the request body to Route.MaxBody.
//   - Apply Route.Timeout and timeout the request if generating a response
//     takes longer.
//   - Authenticate the request. If Route.Auth.Authenticate returns an error
//     the error is sent to the client and the route handler is not invoked.
//   - Handle the request. The Route.Handler.ServeAPI is invoked with the
//     authenticated request.
func (ro Route) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := &Response{
		ResponseWriter: w,
	}
	received := time.Now()

	if r.Method != ro.Method {
		if !(r.Method == http.MethodPost && ro.Method == http.MethodPut) {
			w.Header().Set(headers.Accept, ro.Method)
			resp.Failf(http.StatusMethodNotAllowed, "received method '%s' expected '%s'", r.Method, ro.Method)
			return
		}
	}

	// URL path is not guaranteed to start with a leading '/'
	// Hence, we add it for a canonical representation.
	if len(r.URL.Path) > 0 && r.URL.Path[0] != '/' {
		r.URL.Path = "/" + r.URL.Path
	}
	resource, ok := strings.CutPrefix(r.URL.Path, ro.Path)
	if !ok {
		resp.Failf(http.StatusInternalServerError, "routing error: request '%s' handled by route '%s'", r.URL.Path, ro.Path)
		return
	}

	// Limit request bodies such that handlers can read from it securely.
	if ro.MaxBody >= 0 {
		if r.ContentLength < 0 || r.ContentLength > int64(ro.MaxBody) {
			r.ContentLength = int64(ro.MaxBody)
		}
		r.Body = http.MaxBytesReader(w, r.Body, r.ContentLength)
	}

	// Set a timeout.
	if ro.Timeout > 0 {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(ro.Timeout)); err != nil {
			if errors.Is(err, http.ErrNotSupported) {
				Failf(resp, http.StatusInternalServerError, "route '%s' does not support timeouts", ro.Path)
				return
			}
			resp.Failf(http.StatusInternalServerError, "failed to set timeout on route '%s'", ro.Path)
			return
		}
	}

	req, err := ro.Auth.Authenticate(r)
	if err != nil {
		resp.Failr(err)
		return
	}

	req.Resource = resource
	req.Received = received
	ro.Handler.ServeAPI(resp, req)
}

// A Handler responds to an API request.
//
// ServeAPI should either reply to the client or fail the request and
// then return. The Response type provides methods to do so. Returning
// signals that the request is finished; it is not valid to send a
// Response or read from the Request.Body after or concurrently with
// the completion of the ServeAPI call.
//
// If ServeAPI panics, the HTTP server assumes that the effect of the
// panic was isolated to the active request. It recovers the panic,
// logs a stack trace to the server error log, and either closes the
// network connection or sends an HTTP/2 RST_STREAM, depending on the
// HTTP protocol. To abort a handler so the client sees an interrupted
// response but the server doesn't log an error, panic with the value
// http.ErrAbortHandler.
type Handler interface {
	ServeAPI(*Response, *Request)
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as API handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
type HandlerFunc func(*Response, *Request)

// ServeAPI calls f with the given request and response.
func (f HandlerFunc) ServeAPI(resp *Response, req *Request) {
	f(resp, req)
}

// An Authenticator authenticates HTTP requests.
//
// Authenticate should verify an incoming HTTP request
// and return either an authenticated API request or
// an API error.
type Authenticator interface {
	Authenticate(*http.Request) (*Request, Error)
}

// InsecureSkipVerify is an Authenticator that does not verify
// incoming HTTP requests in any way. It should only be used
// for routes that do neither wish to authenticate requests nor
// care about the client identity.
var InsecureSkipVerify Authenticator = insecureSkipVerify{}

type insecureSkipVerify struct{}

func (insecureSkipVerify) Authenticate(r *http.Request) (*Request, Error) {
	return &Request{Request: r}, nil
}

// Request is an authenticated HTTP request.
type Request struct {
	*http.Request

	Identity kes.Identity

	Resource string

	Received time.Time
}

// LogValue returns the requests logging representation.
func (r *Request) LogValue() slog.Value {
	var identity string
	if r.Identity.IsUnknown() {
		identity = "<unknown>"
	} else {
		identity = r.Identity.String()
	}
	ip, _ := netip.ParseAddrPort(r.RemoteAddr)
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("ip", ip.Addr().String()),
		slog.String("identity", identity),
	)
}

// Response is an API response.
type Response struct {
	http.ResponseWriter
}

// Reply is a shorthand for api.Reply. It sends just an HTTP
// status code to the client. The response body is empty.
func (r *Response) Reply(code int) { Reply(r, code) }

// Fail is a shorthand for api.Fail. It responds to the client
// with the given status code and error message.
func (r *Response) Fail(code int, msg string) error { return Fail(r, code, msg) }

// Failf is a shorthand for api.Failf. Failf responds to the
// client with the given status code and formatted error message.
func (r *Response) Failf(code int, format string, v ...any) error {
	return Failf(r, code, format, v...)
}

// Failr is a shorthand for api.Failr. Failr responds to the
// client with err.
func (r *Response) Failr(err Error) error { return Failr(r, err) }

// Reply sends just an HTTP status code to the client.
// The response body is empty.
func Reply(r *Response, code int) {
	r.Header().Set(headers.ContentLength, strconv.Itoa(0))
	r.WriteHeader(code)
}

// ReplyWith sends an HTTP status code and the data as response
// body to the client. The data format is selected automatically
// based on the response content encoding.
func ReplyWith(r *Response, code int, data any) error {
	r.Header().Set(headers.ContentType, headers.ContentTypeJSON)
	r.WriteHeader(code)
	return json.NewEncoder(r).Encode(data)
}

// ReadBody reads the request body into v using the
// request content encoding.
//
// ReadBody assumes that the request body is limited to a
// reasonable size. It may return an error if it cannot
// determine the request content length before decoding.
func ReadBody(r *Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
