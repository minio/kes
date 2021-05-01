// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"
)

// retryBody takes an io.ReadSeeker and converts it
// into an io.ReadCloser that can be used as request
// body for retryable requests.
//
// The body must implement io.Seeker to ensure that
// the entire body is sent again when retrying a request.
//
// If body is nil, retryBody returns nil.
func retryBody(body io.ReadSeeker) io.ReadCloser {
	if body == nil {
		return nil
	}

	var closer io.Closer
	if c, ok := body.(io.Closer); ok {
		closer = c
	} else {
		closer = ioutil.NopCloser(body)
	}

	type ReadSeekCloser struct {
		io.ReadSeeker
		io.Closer
	}
	return ReadSeekCloser{
		ReadSeeker: body,
		Closer:     closer,
	}
}

// requestOption is and optional parameter of an HTTP request.
type requestOption func(*http.Request)

// withHeader returns a requestOption that sets the given
// key-value pair as HTTP header.
func withHeader(key, value string) requestOption {
	return func(req *http.Request) {
		req.Header.Set(key, value)
	}
}

// retry is an http.Client that implements
// a retry mechanism for requests that fail
// due to a temporary network error.
//
// It provides a similar interface as the http.Client
// but requires that the request body implements io.Seeker.
// Otherwise, it cannot guarantee that the entire request
// body gets sent when retrying a request.
type retry http.Client

// Send creates a new HTTP request with the given method, context
// request body and request options, if any. It randomly iterates
// over the given endpoints until it receives a HTTP response.
//
// If sending a request to one endpoint fails due to e.g. a network
// or DNS error, Send tries the next endpoint. It aborts once the
// context is canceled or its deadline exceeded.
func (r *retry) Send(ctx context.Context, method string, endpoints []string, path string, body io.ReadSeeker, options ...requestOption) (*http.Response, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("kes: no server endpoint")
	}
	var (
		request  *http.Request
		response *http.Response
		err      error
		R        = rand.Intn(len(endpoints)) // randomize endpoints => avoid hitting the same endpoint all the time.
	)
	for i := range endpoints {
		nextEndpoint := endpoints[(i+R)%len(endpoints)]
		request, err = http.NewRequestWithContext(ctx, method, endpoint(nextEndpoint, path), retryBody(body))
		if err != nil {
			return nil, err
		}
		for _, opt := range options {
			opt(request)
		}

		response, err = r.Do(request)
		if err == nil {
			return response, nil
		}
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}
	return response, err
}

// Get issues a GET to the specified URL.
// It is a wrapper around retry.Do.
func (r *retry) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, retryBody(nil))
	if err != nil {
		return nil, err
	}
	return r.Do(req)
}

// Post issues a POST to the specified URL.
// It is a wrapper around retry.Do.
func (r *retry) Post(url, contentType string, body io.ReadSeeker) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, retryBody(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return r.Do(req)
}

// Do sends an HTTP request and returns an HTTP response using
// the underlying http.Client. If the request fails b/c of a
// temporary error Do retries the request a few times. If the
// request keeps failing, Do will give up and return a descriptive
// error.
func (r *retry) Do(req *http.Request) (*http.Response, error) {
	type RetryReader interface {
		io.Reader
		io.Seeker
		io.Closer
	}

	// If the request body is not a RetryReader it cannot
	// be retried. The caller has to ensure that the actual
	// body content is an io.ReadCloser + io.Seeker.
	// The retry.NewRequest method does that.
	//
	// A request can only be retried if we can seek to the
	// start of the request body. Otherwise, we may send a
	// partial response body when we retry the request.
	var body RetryReader
	if req.Body != nil {
		var ok bool
		body, ok = req.Body.(RetryReader)
		if !ok {
			// We cannot convert the req.Body to an io.Seeker.
			// If we would proceed we may introduce hard to find
			// bugs. Also, there is no point in returning an
			// error since the caller has specified a wrong type.
			panic("kes: request cannot be retried")
		}
	}

	const (
		MinRetryDelay     = 200 * time.Millisecond
		MaxRandRetryDelay = 800
	)
	var (
		retry  = 2 // For now, we retry 2 times before we give up
		client = (*http.Client)(r)
	)
	resp, err := client.Do(req)
	for retry > 0 && (isTemporary(err) || (resp != nil && resp.StatusCode == http.StatusServiceUnavailable)) {
		randomRetryDelay := time.Duration(rand.Intn(MaxRandRetryDelay)) * time.Millisecond
		time.Sleep(MinRetryDelay + randomRetryDelay)
		retry--

		// If there is a body we have to reset it. Otherwise, we may send
		// only partial data to the server when we retry the request.
		if body != nil {
			if _, err = body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			req.Body = body
		}

		resp, err = client.Do(req) // Now, retry.
	}
	if isTemporary(err) {
		// If the request still fails with a temporary error
		// we wrap the error to provide more information to the
		// caller.
		return nil, &url.Error{
			Op:  req.Method,
			URL: req.URL.String(),
			Err: fmt.Errorf("Temporary network error: %v", err),
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
