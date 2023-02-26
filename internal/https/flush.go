// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import (
	"net/http"
)

// FlushOnWrite returns an ResponseWriter that wraps w and
// flushes after every Write if w implements the Flusher
// interface.
func FlushOnWrite(w http.ResponseWriter) http.ResponseWriter {
	f, _ := w.(http.Flusher)
	return &flushWriter{
		w: w,
		f: f,
	}
}

type flushWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

var ( // compiler checks
	_ http.ResponseWriter = (*flushWriter)(nil)
	_ http.Flusher        = (*flushWriter)(nil)
)

// Unwrap returns the underlying ResponseWriter.
//
// This method is mainly used in the context of ResponseController.
func (fw *flushWriter) Unwrap() http.ResponseWriter { return fw.w }

func (fw *flushWriter) WriteHeader(status int) { fw.w.WriteHeader(status) }

func (fw *flushWriter) Header() http.Header { return fw.w.Header() }

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.Write(p)
	if fw.f != nil && err == nil {
		fw.f.Flush()
	}
	return n, err
}

func (fw *flushWriter) Flush() {
	if fw.f != nil {
		fw.f.Flush()
	}
}
