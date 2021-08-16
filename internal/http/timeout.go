// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"log"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Timeout returns an HTTP handler that aborts f
// after the given time limit.
//
// The request times out when it takes longer then
// the given time limit to read the request body
// and write a response back to the client.
//
// Once the timeout exceeds, any further Write call
// by f to the http.ResponseWriter will return
// http.ErrHandlerTimeout. Further, if the timeout
// exceeds before f writes an HTTP status code then
// Timeout will return 503 ServiceUnavailable to the
// client.
//
// Timeout cancels the request context before aborting f.
func Timeout(after time.Duration, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			doneCh  = make(chan struct{})
			panicCh = make(chan interface{}, 1)
		)
		var tw = &timeoutResponseWriter{
			ResponseWriter: w,
		}
		if f, ok := w.(http.Flusher); ok {
			tw.Flusher = f
		}
		if p, ok := w.(http.Pusher); ok {
			tw.Pusher = p
		}

		ctx, cancelCtx := context.WithCancel(r.Context())
		defer cancelCtx()
		r = r.WithContext(ctx)

		// We start f in a separate Go routine and wait until it
		// completes resp. the timer expires - whatever happens first.
		//
		// Further, we have to recover from any potential panic that
		// gets raised by f. However, we must not propagate the panic
		// since that would shadow the actual location where the panic
		// occurred. Instead, write a log message to the HTTP server error
		// log - similar to the standard library - and abort the handler
		// by panic'ing ErrAbortHandler.
		go func() {
			defer func() {
				err := recover()
				if err != nil && err != http.ErrAbortHandler {
					const size = 64 << 10
					buf := make([]byte, size)
					buf = buf[:runtime.Stack(buf, false)]

					srv := r.Context().Value(http.ServerContextKey).(*http.Server)
					if srv != nil && srv.ErrorLog != nil {
						srv.ErrorLog.Printf("http: panic serving %v: %v\n%s", r.RemoteAddr, err, buf)
					} else {
						log.Printf("http: panic serving %v: %v\n%s", r.RemoteAddr, err, buf)
					}
				}
				if err != nil {
					panicCh <- http.ErrAbortHandler
				}
			}()
			f(tw, r)
			close(doneCh)
		}()

		timer := time.NewTimer(after)
		defer timer.Stop()
		select {
		case err := <-panicCh:
			panic(err)
		case <-timer.C:
			cancelCtx()
			tw.timeout()
		case <-ctx.Done():
		case <-doneCh:
		}
	}
}

// timeoutResponseWriter is an http.ResponseWriter
// that can time out. Once it has timed out, any
// further subsequent Write will return http.ErrHandlerTimeout.
type timeoutResponseWriter struct {
	http.ResponseWriter
	http.Flusher
	http.Pusher

	writeHeaderHappened uint32
	timedOut            uint32
}

// timeout marks the ResponseWriter as timed out.
//
// If no HTTP status code has been written already,
// then timeout will send the HTTP status code 503
// service unavailable to the client.
func (w *timeoutResponseWriter) timeout() {
	atomic.StoreUint32(&w.timedOut, 1)
	if atomic.CompareAndSwapUint32(&w.writeHeaderHappened, 0, 1) {
		w.ResponseWriter.WriteHeader(http.StatusServiceUnavailable)
	}
}

func (w *timeoutResponseWriter) Write(p []byte) (int, error) {
	if atomic.LoadUint32(&w.timedOut) == 1 {
		return 0, http.ErrHandlerTimeout
	}

	if atomic.CompareAndSwapUint32(&w.writeHeaderHappened, 0, 1) {
		w.ResponseWriter.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *timeoutResponseWriter) WriteHeader(statusCode int) {
	if atomic.LoadUint32(&w.timedOut) == 1 {
		return
	}

	if atomic.CompareAndSwapUint32(&w.writeHeaderHappened, 0, 1) {
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *timeoutResponseWriter) Flush() {
	if w.Flusher != nil {
		w.Flusher.Flush()
	}
}

func (w *timeoutResponseWriter) Push(target string, opts *http.PushOptions) error {
	if w.Pusher != nil {
		return w.Pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}
