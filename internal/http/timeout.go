// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
)

// Timeout returns an HTTP handler that runs f
// with the given time limit.
//
// A timeout is triggered if there is no activity
// within the given time limit.
//
// If the time limit exceeds before f has written
// any response to the client, Timeout will return
// http.StatusServiceUnavailable (503) to the client.
//
// If the time limit exceeds after f has written
// a response to the client - without any further
// activity - Timeout will send two (non-empty)
// HTTP trailers:
//   • Status: http.StatusServiceUnavailable
//   • Error: {"message":"timeout"}
//
// In any case, the timeout handler eventually closes
// the underlying connection. Any further attempt by f
// to write to the client after the timeout limit has
// been exceeded will fail with http.ErrHandlerTimeout.
//
// If f implements a long-running job then it should either
// stop once request.Context().Done() completes or once
// a http.ResponseWriter.Write(...) call returns http.ErrHandlerTimeout.
//
// If f returns a stream (of messages) to the client then
// it must send another message to the client before the
// the time limit exceeds and must send the HTTP trailers:
//   • Status: "200"
//   • Error:  ""
// once it completes successfully.
// If f fails after streaming at least one message to the
// client it should use ErrorTrailer to send the error as
// HTTP trailer to the client.
func Timeout(after time.Duration, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		r = r.WithContext(ctx)
		tw := newTimeoutWriter(w)
		tw.Header().Set("Trailer", "Status, Error")

		done := make(chan struct{})
		panicChan := make(chan interface{}, 1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			f(tw, r)
			close(done)
		}()

		timer := time.NewTimer(after)
		defer timer.Stop()
		for {
			select {
			case p := <-panicChan:
				panic(p)
			case <-timer.C:
				if tw.isInactive() {
					tw.timeout()
					return
				}
				tw.markInactive()
				timer.Reset(after)
			case <-ctx.Done():
				tw.timeout()
				return
			case <-done:
				return
			}
		}
	}
}

// timeoutWriter is a http.ResponseWriter that implements
// http.Flusher and http.Pusher. It synchronizes a potential
// timeout and the writes by the http.ResponseWriter it wraps.
type timeoutWriter struct {
	writer  http.ResponseWriter
	flusher http.Flusher
	pusher  http.Pusher

	writeHappened uint32

	lock       sync.Mutex
	timedOut   bool
	hasWritten bool
}

var _ http.ResponseWriter = (*timeoutWriter)(nil)
var _ http.Flusher = (*timeoutWriter)(nil)
var _ http.Pusher = (*timeoutWriter)(nil)

var errTimeout = kes.NewError(http.StatusServiceUnavailable, "timeout")

func newTimeoutWriter(w http.ResponseWriter) *timeoutWriter {
	tw := &timeoutWriter{
		writer: w,
	}
	if flusher, ok := w.(http.Flusher); ok {
		tw.flusher = flusher
	}
	if pusher, ok := w.(http.Pusher); ok {
		tw.pusher = pusher
	}
	return tw
}

// timeout returns http.StatusServiceUnavailable to the client
// if no response has been written to the client, yet.
func (tw *timeoutWriter) timeout() {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	tw.timedOut = true
	if !tw.hasWritten {
		tw.hasWritten = true
		Error(tw.writer, errTimeout)
	} else {
		ErrorTrailer(tw.writer, errTimeout)
	}
}

// isInactive returns true if no Write has happened
// ever resp. since the last call to markInactive.
func (tw *timeoutWriter) isInactive() bool { return atomic.LoadUint32(&tw.writeHappened) == 0 }

// markInactive marks the http.ResponseWriter as
// inactive. Another call to Write marks it as
// active again.
func (tw *timeoutWriter) markInactive() { atomic.StoreUint32(&tw.writeHappened, 0) }

func (tw *timeoutWriter) Header() http.Header { return tw.writer.Header() }

func (tw *timeoutWriter) WriteHeader(statusCode int) {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	if tw.timedOut {
		if !tw.hasWritten {
			tw.hasWritten = true
			Error(tw.writer, errTimeout)
		}
	} else {
		tw.hasWritten = true
		tw.writer.WriteHeader(statusCode)
	}
}

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	// We must not hold the lock while writing to the
	// underlying http.ResponseWriter (via Write([]byte))
	// b/c e.g. a slow/malicious client would block the
	// lock.Unlock.
	// In this case we cannot accquire the lock when we
	// want to mark the timeoutWriter as timed out (See: timeout()).
	// So, the client would block the actual handler by slowly
	// reading the response and the timeout handler since it
	// would not be able to accquire the lock until the Write([]byte)
	// finishes.
	// Therefore, we must release the lock before writing
	// the (eventually large) response body to the client.
	tw.lock.Lock()
	if tw.timedOut {
		tw.lock.Unlock()
		return 0, http.ErrHandlerTimeout
	}
	if !tw.hasWritten {
		tw.hasWritten = true
		tw.writer.WriteHeader(http.StatusOK)
	}
	tw.lock.Unlock()

	atomic.StoreUint32(&tw.writeHappened, 1)
	return tw.writer.Write(p)
}

func (tw *timeoutWriter) Flush() {
	if tw.flusher != nil {
		tw.flusher.Flush()
	}
}

func (tw *timeoutWriter) Push(target string, opts *http.PushOptions) error {
	if tw.pusher != nil {
		return tw.pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}
