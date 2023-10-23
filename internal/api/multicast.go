// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
)

// Multicast is a one-to-many io.Writer. It is similar
// to io.MultiWriter but writers can be added and removed
// dynamically. A Multicast may be modified by multiple
// go routines concurrently.
//
// Its zero value is an empty group of io.Writers and
// ready for use.
type Multicast struct {
	group atomic.Pointer[[]io.Writer]
}

// Num returns how many connections are part of this Multicast.
func (m *Multicast) Num() int {
	if p := m.group.Load(); p != nil {
		return len(*p)
	}
	return 0
}

// Add adds w to m. Future writes to m will also reach w.
// If w is already part of m, Add does nothing.
func (m *Multicast) Add(w io.Writer) {
	if w == nil {
		return
	}

	for {
		old := m.group.Load()
		if old == nil && m.group.CompareAndSwap(nil, &[]io.Writer{w}) {
			return
		}
		if slices.Contains(*old, w) { // avoid adding an io.Writer twice
			return
		}

		group := make([]io.Writer, 0, len(*old)+1)
		group = append(group, w)
		group = append(group, *old...)
		if m.group.CompareAndSwap(old, &group) {
			return
		}
	}
}

// Remove removes w from m. Future writes to m will no longer
// reach w.
func (m *Multicast) Remove(w io.Writer) {
	if w == nil {
		return
	}

	for {
		old := m.group.Load()
		if old == nil || len(*old) == 0 || !slices.Contains(*old, w) {
			return
		}

		group := make([]io.Writer, 0, len(*old)-1)
		for _, wr := range *old {
			if wr != w {
				group = append(group, wr)
			}
		}
		if m.group.CompareAndSwap(old, &group) {
			return
		}
	}
}

// Write writes p to all io.Writers that are currently part of m.
// It returns the first error encountered, if any, but writes to
// all io.Writers before returning.
func (m *Multicast) Write(p []byte) (n int, err error) {
	ptr := m.group.Load()
	if ptr == nil {
		return 0, nil
	}
	group := *ptr
	if len(group) == 0 {
		return 0, nil
	}

	for _, w := range group {
		nn, wErr := w.Write(p)
		if wErr == nil && nn < len(p) {
			wErr = io.ErrShortWrite
		}
		if err == nil && wErr != nil {
			err = wErr
			n = nn
		}
	}
	if n == 0 && err == nil {
		n = len(p)
	}
	return n, err
}

// LogWriter wraps an io.Writer and encodes each
// write operation as ErrorLogEvent.
//
// It's intended to be used as adapter to send
// API error logs to an http.ResponseWriter.
type LogWriter struct {
	encoder *json.Encoder
	flusher http.Flusher
}

// NewLogWriter returns a new LogWriter wrapping w.
func NewLogWriter(w io.Writer) *LogWriter {
	flusher, _ := w.(http.Flusher)
	return &LogWriter{
		encoder: json.NewEncoder(w),
		flusher: flusher,
	}
}

// Write encodes p as ErrorLogEvent and
// writes it to the underlying io.Writer.
func (w *LogWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	n := len(p)
	if p[n-1] == '\n' { // Remove trailing newline added by logger
		p = p[:n-1]
	}

	if err := w.encoder.Encode(ErrorLogEvent{
		Message: string(p),
	}); err != nil {
		return 0, err
	}
	if w.flusher != nil {
		w.flusher.Flush()
	}
	return n, nil
}
