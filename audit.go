// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// SystemLog groups a set of logging targets.
// It holds a reference to a *log.Logger which
// gets updated whenever a log target gets added
// or removed.
// Since this can happen concurrently, it is not
// recommended to set the log output of SystemLog.Logger()
// manually. Instead, modify the *log.Logger output
// through the SystemLog API.
type SystemLog struct {
	lock   sync.Mutex
	output []io.Writer
	logger *log.Logger
}

// NewLogger creates a new SystemLog. The out variable sets the
// destination to which log data will be written. The prefix
// appears at the beginning of each generated log line. The
// flag argument defines the logging properties.
func NewLogger(out io.Writer, prefix string, flags int) *SystemLog {
	logger := &SystemLog{
		output: []io.Writer{out},
	}
	logger.logger = log.New(io.MultiWriter(logger.output...), prefix, flags)
	return logger
}

// SetOutput sets the output destination for the logger.
func (l *SystemLog) SetOutput(out ...io.Writer) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.output = make([]io.Writer, len(out))
	copy(l.output, out)
	l.logger.SetOutput(io.MultiWriter(l.output...))
}

// AddOutput adds an output destination to the logger.
func (l *SystemLog) AddOutput(out io.Writer) {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.output = append(l.output, out)
	l.logger.SetOutput(io.MultiWriter(l.output...))
}

// RemoveOutput removes the output destination from the
// logger, if it exists.
func (l *SystemLog) RemoveOutput(out io.Writer) {
	l.lock.Lock()
	defer l.lock.Unlock()

	output := make([]io.Writer, 0, len(l.output))
	for i := range l.output {
		if out != l.output[i] {
			output = append(output, l.output[i])
		}
	}
	l.output = output
	l.logger.SetOutput(io.MultiWriter(output...))
}

// Log returns the actual logger that writes everything
// to the currently specified output destination.
func (l *SystemLog) Log() *log.Logger { return l.logger }

var _ http.ResponseWriter = (*auditResponseWriter)(nil)
var _ http.Flusher = (*auditResponseWriter)(nil)

// auditResponseWriter is an http.ResponseWriter implementation
// that logs (parts of) the request and response before sending
// the status code back to the client.
type auditResponseWriter struct {
	http.ResponseWriter

	URL           url.URL     // The request URL
	Identity      Identity    // The request X.509 identity
	RequestHeader http.Header // The request headers
	Time          time.Time   // The time when we receive the request

	logger  *log.Logger
	written bool // Set to true on first write
}

func (w *auditResponseWriter) Header() http.Header {
	return w.ResponseWriter.Header()
}

func (w *auditResponseWriter) WriteHeader(statusCode int) {
	if !w.written {
		w.written = true

		now := time.Now().UTC()
		const format = `{"time":"%s","request":{"path":"%s","identity":"%s"},"response":{"code":%d, "time":%d}}`
		w.logger.Printf(format, now.Format(time.RFC3339), w.URL.Path, w.Identity, statusCode, now.Sub(w.Time.UTC()))

		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func (w *auditResponseWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *auditResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// A flushWriter wraps and io.Writer and performs
// a flush operation after every write call if the
// wrapped io.Writer implements http.Flusher.
//
// A flushWriter is useful when (even small) data
// should reach the receiver as soon as possible.
// For example, in case of audit logging.
type flushWriter struct {
	io.Writer
	http.Flusher
}

// newFlushWriter returns a new flushWriter that
// wraps w and flushes everything written to it
// as soon as possible if w implements http.Flusher.
func newFlushWriter(w io.Writer) flushWriter {
	fw := flushWriter{Writer: w}
	if flusher, ok := w.(http.Flusher); ok {
		fw.Flusher = flusher
	}
	return fw
}

func (w flushWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if w.Flusher != nil {
		// TODO(aead): Flushing after every write may
		// be not very efficient (benchmarks required!)
		// since we perform one/multiple system calls
		// per write.
		// However, buffering does not seem possible
		// since a flushWriter is in particularly used for
		// audit log tracing and we cannot afford loosing
		// an audit event.
		// Therefore, no (more) efficient solution known, yet.
		w.Flusher.Flush()
	}
	return n, err
}
