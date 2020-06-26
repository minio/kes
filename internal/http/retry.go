// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RetryReader returns an io.ReadSeeker that can be
// used as request body for retriable requests via
// Seek(0, io.SeekStart).
// The returned io.ReadSeeker implements io.Closer.
//
// If r does not implement io.Closer RetryReader returns
// an io.ReadSeeker that implements io.Closer as nop.
func RetryReader(r io.ReadSeeker) io.ReadSeeker {
	if _, ok := r.(io.Closer); ok {
		return r
	}
	return nopCloser{r}
}

type nopCloser struct{ io.ReadSeeker }

func (nopCloser) Close() error { return nil }

// Retry wraps an HTTP client and retries requests
// when they fail because of a temporary network
// error or a 5xx response status code.
//
// Its zero value is a usable client that uses
// http.DefaultTransport and may retry a request
// a few times before giving up.
//
// If a request contains a non-nil body then this
// body must implement io.Seeker. Any io.ReadSeeker
// can be turned into a requst body via the RetryReader
// function.
//
// Retry retries a request at most N times and waits
// at least Delay and at most Delay + Jitter before
// sending the request again. If not specified then
// Retry uses sane default values for N, Delay and Jitter.
type Retry struct {
	// Client is the underlying HTTP client.
	// Using Client directly bypasses the
	// retry mechanism.
	http.Client

	// N is the number of retry attempts. If a request
	// fails because of a temporary network error or
	// 5xx response code then Retry keeps sending the
	// same request N times before giving up and returning
	// the last error encountered.
	N uint

	// Delay is the duration Retry waits at least before
	// retrying a request.
	Delay time.Duration

	// Jitter is the maximum duration Retry adds to Delay.
	// Retry waits at most Delay + Jitter before retrying
	// a request.
	//
	// In particular, Retry chooses a pseudo-random
	// duration [0, Jitter) and adds it do Delay.
	Jitter time.Duration
}

// Get issues a GET to the specified URL as specified by http.Client.
// It follows redirects after calling the underlying Client's
// CheckRedirect function.
//
// If the GET fails due to a temporary network error or 5xx server
// response then GET retries the request N times.
func (r *Retry) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return r.Do(req)
}

// Head issues a HEAD to the specified URL as specified by http.Client.
// It follows redirects after calling the underlying Client's
// CheckRedirect function.
//
// If the HEAD fails due to a temporary network error or 5xx server
// response then Head retries the request N times.
func (r *Retry) Head(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	return r.Do(req)
}

// Post issues a POST to the specified URL as specified by http.Client.
// The provided body must implement io.Seeker and io.Closer. To obtain
// an io.Closer from an io.ReadSeeker refer to the RetryReader function.
//
// Caller should close resp.Body when done reading from it.
//
// If the POST fails due to a temporary network error or 5xx server
// response the Post retries the request N times.
//
// See the Retry.Do method documentation for details on how redirects
// are handled.
func (r *Retry) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return r.Do(req)
}

// PostForm issues a POST to the specified URL as specified by http.Client,
// with data's keys and values URL-encoded as the request body.
//
// The Content-Type header is set to application/x-www-form-urlencoded.
//
// If the POST fails due to a temporary network error or 5xx server
// response the Post retries the request N times.
//
// See the Client.Do method documentation for details on how redirects
// are handled.
func (r *Retry) PostForm(url string, data url.Values) (*http.Response, error) {
	return r.Post(url, "application/x-www-form-urlencoded", RetryReader(strings.NewReader(data.Encode())))
}

// Do sends an HTTP request and returns an HTTP response, following
// policy (such as redirects, cookies, auth) as configured on the
// client and as specified by http.Client.
//
// If the request fails due to a temporary network error or the server
// returns a 5xx response then Do retries the request N times.
//
// If non-nil, the request body must implement io.Seeker.
//
// Any returned error will be of type *url.Error. The url.Error
// value's Timeout method will report true if request timed out or was
// canceled.
func (r *Retry) Do(req *http.Request) (*http.Response, error) {
	var (
		N      = r.N
		Delay  = r.Delay
		Jitter = r.Jitter
	)
	if N == 0 {
		N = 2 // default to 2 re-tries
	}
	if Delay == 0 {
		Delay = 200 * time.Millisecond // default to waiting at least 200ms
	}
	if Jitter == 0 {
		Jitter = 800 * time.Millisecond // default to waiting at most r.Delay + 800ms
	}

	type RetryReader interface {
		io.Reader
		io.Seeker
		io.Closer
	}

	var body RetryReader
	if req.Body != nil {
		var ok bool
		body, ok = req.Body.(RetryReader)
		if !ok {
			return nil, &url.Error{
				Op:  req.Method,
				URL: req.URL.String(),
				Err: errors.New("http: request body does not implemement io.Seeker"),
			}
		}
	}

	resp, err := r.Client.Do(req)
	for N > 0 && (isTemporary(err) || (resp != nil && resp.StatusCode >= http.StatusInternalServerError)) {
		N--
		var delay time.Duration
		switch {
		case Jitter < time.Microsecond:
			delay = Delay + time.Duration(rand.Int63n(int64(Jitter)))*time.Nanosecond
		case Jitter < time.Millisecond:
			delay = Delay + time.Duration(rand.Int63n(int64(Jitter)))*time.Microsecond
		default:
			delay = Delay + time.Duration(rand.Int63n(Jitter.Milliseconds()))*time.Millisecond
		}

		timer := time.NewTimer(delay)
		select {
		case <-req.Context().Done():
			timer.Stop()
			return nil, &url.Error{
				Op:  req.Method,
				URL: req.URL.String(),
				Err: req.Context().Err(),
			}
		case <-timer.C:
			timer.Stop()
		}

		// If there is a body we have to reset it. Otherwise, we may send
		// only partial data to the server when we retry the request.
		if body != nil {
			if _, err = body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			req.Body = body
		}
		resp, err = r.Client.Do(req) // Now, retry.
	}
	if isTemporary(err) {
		// If the request still fails with a temporary error
		// we wrap the error to provide more information to the
		// caller.
		return nil, &url.Error{
			Op:  req.Method,
			URL: req.URL.String(),
			Err: fmt.Errorf("http: temporary network error: %v", err),
		}
	}
	return resp, err
}

// isTemporary returns true if the given error is
// temporary - e.g. a temporary *url.Error or an
// net.Error that indicates that a request got
// timed-out.
//
// A nil error is not temporary.
func isTemporary(err error) bool {
	if err == nil { // fast path
		return false
	}
	if netErr, ok := err.(net.Error); ok { // *url.Error implements net.Error
		if netErr.Timeout() || netErr.Temporary() {
			return true
		}

		// If a connection drops (e.g. server dies) while sending the request
		// http.Do returns either io.EOF or io.ErrUnexpected. We treat that as
		// temp. since the server may get restared such that the retry may succeed.
		if errors.Is(netErr, io.EOF) || errors.Is(netErr, io.ErrUnexpectedEOF) {
			return true
		}
	}
	return false
}
