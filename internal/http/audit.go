// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/minio/kes"
)

// AuditResponseWriter is an http.ResponseWriter that
// writes a kes.AuditEvent to a log.Logger after sending
// the response status code and before response body.
type AuditResponseWriter struct {
	http.ResponseWriter

	// Logger will receive the kes.AuditEvent produced
	// on the first invocation of Write resp. WriteHeader.
	Logger *log.Logger

	URL      url.URL      // The request URL
	Identity kes.Identity // The client's X.509 identity
	Time     time.Time    // The time when we receive the request

	sentHeader bool // Set to true on first WriteHeader
}

var (
	_ http.ResponseWriter = (*AuditResponseWriter)(nil)
	_ http.Flusher        = (*AuditResponseWriter)(nil)
)

// WriteHeader writes the given statusCode to the underlying
// http.ResponseWriter and then writes a kes.AuditEvent to
// w's log.Logger.
//
// WriteHeader does not produce another kes.AuditEvent when
// invoked again.
func (w *AuditResponseWriter) WriteHeader(statusCode int) {
	if !w.sentHeader { // Avoid logging an event twice
		w.sentHeader = true
		w.ResponseWriter.WriteHeader(statusCode) // Sent the status code BEFORE logging the event

		event := kes.AuditEvent{
			Time: w.Time,
			Request: kes.AuditEventRequest{
				Path:     w.URL.Path,
				Identity: w.Identity.String(),
			},
			Response: kes.AuditEventResponse{
				StatusCode: statusCode,
				Time:       time.Now().UTC().Sub(w.Time.UTC()),
			},
		}
		w.Logger.Print(event.String()) // The string representation of a kes.AuditEvent is JSON
	}
}

// Write writes b to the underlying http.ResponseWriter.
// If no status code has been sent via WriteHeader, Write
// sends the status code 200 OK.
func (w *AuditResponseWriter) Write(b []byte) (int, error) {
	if !w.sentHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush flushes whatever has been written to w to the
// receiver.
func (w *AuditResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
