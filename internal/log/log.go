// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
)

// These flags define how a Logger generates text for each log entry.
// Flags are or'ed together to control what gets printed. With the
// exception of the Lmsgprefix flag, there is no control over they
// appear or the format they present.
// The prefix is followed by a colon only when Llongfile or Lshortfile
// is specified.
// For example, flags Ldata | Ltime prodcue:
//
//	2023/01/01 01:23:45 message
//
// while flags Ldate | Ltime | Lmicroseconds | Llongfile produce,
//
//	2023/01/01 01:23:45.123456 /a/b/c/d.go:23: message
const (
	Ldate         = log.Ldate         // the date in the local time zone: 2023/01/01
	Ltime         = log.Ltime         // the time in the local time zone: 01:23:45
	Lmicroseconds = log.Lmicroseconds // microsecond resolution: 01:23:45.123456.  assumes Ltime.
	Llongfile     = log.Llongfile     // full file name and line number: /a/b/c/d.go:23
	Lshortfile    = log.Lshortfile    // final file name element and line number: d.go:23. overrides Llongfile
	LUTC          = log.LUTC          // if Ldate or Ltime is set, use UTC rather than the local Ltime zone
	Lmsgprefix    = log.Lmsgprefix    // move the "prefix" from the beginning of the line to before the message
)

var std = New(os.Stderr, "Error: ", Ldate|Ltime|Lmsgprefix)

// Default returns the package-level logger.
//
// By default, the logger writes to os.Stderr
// with an "Error" prefix and the flags:
//
//	Ldate | Ltime | Lmsgprefx
func Default() *Logger { return std }

// Print writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Print.
func Print(v ...any) { std.Print(v...) }

// Printf writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Printf.
func Printf(format string, v ...any) { std.Printf(format, v...) }

// Println writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Println.
func Println(v ...any) { std.Println(v...) }

// New creates a new Logger. The out is the destination to which
// log data will be written. The prefix appears at the beginning
// of each generated log line, or after the log header if the
// Lmsgprefix flag is provided. The flag argument defines the
// logging properties.
func New(out io.Writer, prefix string, flags int) *Logger {
	mv := new(multiWriter)
	mv.Add(out)

	return &Logger{
		log: log.New(mv, prefix, flags),
		out: mv,
	}
}

// A Logger represents an active logging object that generates lines of
// output to one or multiple io.Writer. Each logging operation makes a
// single call to the Writer's Write method. A Logger can be used
// simultaneously from multiple goroutines; it guarantees to serialize
// access to the Writer.
type Logger struct {
	log *log.Logger
	out *multiWriter
}

// Print writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Print.
func (l *Logger) Print(v ...any) { l.log.Print(v...) }

// Printf writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Printf.
func (l *Logger) Printf(format string, v ...any) { l.log.Printf(format, v...) }

// Println writes to the standard logger.
// Arguments are handled in the manner
// of fmt.Println.
func (l *Logger) Println(v ...any) { l.log.Println(v...) }

// Add adds one or multiple io.Writer as output to
// the logger.
func (l *Logger) Add(out ...io.Writer) { l.out.Add(out...) }

// Remove removes one or multiple io.Writer from the
// logging output.
func (l *Logger) Remove(out ...io.Writer) { l.out.Remove(out...) }

// Log returns a new standard library log.Logger with
// logger's output, prefix and flags.
func (l *Logger) Log() *log.Logger { return log.New(l.log.Writer(), l.log.Prefix(), l.log.Flags()) }

// Writer returns the output destination for the logger.
func (l *Logger) Writer() io.Writer { return l.out }

// SetPrefix sets the output prefix for the logger.
func (l *Logger) SetPrefix(prefix string) { l.log.SetPrefix(prefix) }

// ErrEncoder is an io.Writer that converts all
// log messages into a stream of kes.ErrorEvents.
//
// An ErrEncoder should be used when converting
// log messages to JSON.
type ErrEncoder struct {
	encoder *json.Encoder
}

// NewErrEncoder returns a new ErrEncoder that
// writes kes.ErrorEvents to w.
func NewErrEncoder(w io.Writer) *ErrEncoder {
	return &ErrEncoder{
		encoder: json.NewEncoder(w),
	}
}

// Write converts p into an kes.ErrorEvent and
// writes its JSON representation to the underlying
// io.Writer.
func (w *ErrEncoder) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return w.WriteString("")
	}
	return w.WriteString(string(p))
}

// WriteString converts s into an kes.ErrorEvent and
// writes its JSON representation to the underlying
// io.Writer.
func (w *ErrEncoder) WriteString(s string) (int, error) {
	type Response struct {
		Message string `json:"message"`
	}
	// A log.Logger will add a newline character to each
	// log message. This newline has to be removed since
	// it's not part of the actual error message.
	s = strings.TrimSuffix(s, "\n")

	err := w.encoder.Encode(Response{
		Message: s,
	})
	if err != nil {
		return 0, err
	}
	return len(s), nil
}
