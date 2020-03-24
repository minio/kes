// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/minio/kes"
)

// JSONWriter wraps an io.Writer and converts
// everything written to it into a JSON object
// object.
//
// In particular, it converts the content passed
// to JSONWriter.Write into the following object:
//   {
//     "message":"<content>"
//   }
//
// Note that a JSONWriter does not try to concatinate
// multiple Write calls into the same JSON object.
// The main purpose of a JSONWriter is to convert
// the output of a log.Logger into JSON.
type JSONWriter struct {
	io.Writer
	http.Flusher
}

var (
	_ io.StringWriter = (*JSONWriter)(nil)
	_ http.Flusher    = (*JSONWriter)(nil)
)

// NewJSONWriter returns a new JSONWriter that
// wraps w and converts everything written to it
// into the following JSON object:
//  {
//    "message":"<content"
//  }
func NewJSONWriter(w io.Writer) JSONWriter {
	jw := JSONWriter{Writer: w}
	if flusher, ok := w.(http.Flusher); ok {
		jw.Flusher = flusher
	}
	return jw
}

func (w JSONWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return w.WriteString("")
	}
	return w.WriteString(string(p))
}

func (w JSONWriter) WriteString(s string) (n int, err error) {
	n = len(s) // We have to return len(s) - not the len of the JSON object.

	var (
		event   = kes.ErrorEvent{Message: s}
		newline = strings.HasSuffix(event.Message, "\n")
	)
	if newline {
		// If s contains a newline at the end (added by the log.Logger)
		// we have to remove it. Otherwise, consumers will treat the
		// newline as part of the message.
		event.Message = event.Message[:n-1]
	}

	json, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	if _, err = w.Writer.Write(json); err != nil {
		return 0, err
	}
	if newline {
		// If we have removed the newline (JSON marshaling) then
		// we have to write it now. Otherwise, we would turn
		// lines into one concatenated string.
		if _, err = w.Writer.Write([]byte{'\n'}); err != nil {
			return 0, err
		}
	}

	w.Flush()
	return n, nil
}

func (w JSONWriter) Flush() {
	if w.Flusher != nil {
		w.Flusher.Flush()
	}
}
