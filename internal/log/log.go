// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"sync"
)

// Print either writes the values to out, if non-nil,
// or to the standard logger otherwise.
func Print(out *log.Logger, values ...any) {
	if out == nil {
		log.Print(values...)
	} else {
		out.Print(values...)
	}
}

// Printf formats the values using the format string
// and either writes to out, if non-nil, or to the
// standard logger otherwise.
func Printf(out *log.Logger, format string, values ...any) {
	if out == nil {
		log.Printf(format, values...)
	} else {
		out.Printf(format, values...)
	}
}

// Target groups a set of logging targets.
//
// A message that gets written to the Target.Log
// will be sent to all logging targets.
type Target struct {
	lock    sync.Mutex // protects the log.Logger and its targets
	logger  *log.Logger
	targets []io.Writer
}

// NewTarget creates a new group of logging targets from the
// given targets. Dublicate or nil targets will be filtered out.
//
// If no targets are provided the returned Target will discard
// any log messages.
func NewTarget(targets ...io.Writer) *Target {
	t := &Target{
		targets: make([]io.Writer, 0, len(targets)),
		logger:  log.New(ioutil.Discard, "", log.LstdFlags),
	}
	for i := range targets {
		t.Add(targets[i])
	}
	return t
}

// Add adds the given target to the set of logging targets.
//
// It does not add the given target if it is already in the
// set of logging targets nor if it is nil.
func (t *Target) Add(target io.Writer) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if target == nil {
		return // Do not add nil as a target
	}
	for i := range t.targets {
		if target == t.targets[i] {
			return // The target already exists
		}
	}
	t.targets = append(t.targets, target)
	t.logger.SetOutput(multiWriter(t.targets))
}

// Remove removes the given target from the set of logging
// targets.
func (t *Target) Remove(target io.Writer) {
	t.lock.Lock()
	defer t.lock.Unlock()

	x := make([]io.Writer, 0, len(t.targets))
	for i := range t.targets {
		if target != t.targets[i] {
			x = append(x, t.targets[i])
		}
	}
	t.targets = x
	t.logger.SetOutput(multiWriter(t.targets))
}

// Log returns the log.Logger that writes to all logging targets.
//
// The output of the returned *log.Logger must not be modified
// directly via its SetOutput method. Instead, use the Add
// and Remove methods of Target.
func (t *Target) Log() *log.Logger { return t.logger }

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

// multiWriter is an io.Writer that writes the same data
// to multiple io.Writer sequentually.
//
// multiWriter differs from the io.MultiWriter impementation
// (in the standard library) by not aborting when one io.Writer
// returns an error.
// Instead, it proceeds until it has written the same data
// to all io.Writer and then reports the first error encounterred,
// if any.
//
// For example, if multiple HTTP clients are registered as logging
// targets while the connection to one clients breaks then all
// other clients should still receive log messages. However, the
// io.MultiWriter would stop and not try to write the log messages
// to all clients.
type multiWriter []io.Writer

func (mw multiWriter) Write(p []byte) (int, error) {
	var err error
	for _, w := range mw {
		n, werr := w.Write(p)
		if werr != nil && err == nil {
			err = werr
		}
		if n != len(p) && err == nil {
			err = io.ErrShortWrite
		}
	}
	return len(p), err
}

func (mw multiWriter) WriteString(s string) (int, error) {
	var (
		err error
		p   []byte // lazily initialized if needed
	)
	for _, w := range mw {
		var (
			n    int
			werr error
		)
		if sw, ok := w.(io.StringWriter); ok {
			n, werr = sw.WriteString(s)
		} else {
			if p == nil {
				p = []byte(s)
			}
			n, werr = w.Write(p)
		}
		if werr != nil && err == nil {
			err = werr
		}
		if n != len(p) && err == nil {
			err = io.ErrShortWrite
		}
	}
	return len(s), err
}
