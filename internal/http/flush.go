// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"io"
	"net/http"
)

// A FlushWriter wraps an io.Writer and performs
// a flush operation after every write call if the
// wrapped io.Writer implements http.Flusher.
//
// A FlushWriter is useful when (small) data should
// be sent to the receiver as soon as possible.
//
// A FlushWriter avoids latency added by buffering
// the data. However, it may impact performance since
// it may increase the number of OS syscalls.
type FlushWriter struct {
	w io.Writer

	// Optimization: if f != nil then w implements http.Flusher.
	//
	// We do the w.(http.Flusher) check once when we create a
	// new FlushWriter instead of doing the type check on each
	// Write or Flush call.
	// A f != nil check is cheaper then a type check.
	f http.Flusher
}

var _ http.Flusher = (*FlushWriter)(nil)

// NewFlushWriter returns a new FlushWriter that
// wraps w.
func NewFlushWriter(w io.Writer) FlushWriter {
	fw := FlushWriter{
		w: w,
	}
	if flusher, ok := w.(http.Flusher); ok {
		fw.f = flusher
	}
	return fw
}

func (w FlushWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if w.f != nil {
		// TODO(aead): Currently, we flush after each
		// write - eventually causing one/multiple
		// syscalls per Write.
		// However, buffering is not really an option
		// since the purpose of a FlushWriter is to
		// avoid latency caused by buffering - e.g.
		// a client should receive a small message
		// immediately.
		// Therefore, it seems like there is no more
		// efficient solution.
		w.f.Flush()
	}
	return n, err
}

func (w FlushWriter) Flush() {
	if w.f != nil {
		w.f.Flush()
	}
}
