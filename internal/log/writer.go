// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

import (
	"io"
	"sync"
)

// multiWriter is an io.Writer that writes the same data
// to multiple io.Writer sequentually. A multiWriter may
// be shared and concurrently modified by multiple go
// routines.
//
// In contrast to the io.MultiWriter, it keeps writing
// to all io.Writers even when one or multiple io.Writers
// return a non-nil.
//
// For example, when multiple HTTP clients have subscribed
// to the audit event stream, all other clients should receive
// the audit event even if one connections breaks.
type multiWriter struct {
	lock    sync.RWMutex
	writers []io.Writer
}

func (mw *multiWriter) Add(out ...io.Writer) {
	if len(out) == 0 {
		return
	}
	mw.lock.Lock()
	defer mw.lock.Unlock()

	for _, o := range out {
		if o == nil || o == io.Discard {
			continue
		}
		if mv, ok := o.(*multiWriter); ok {
			mv.lock.RLock()
			mw.writers = append(mw.writers, mv.writers...)
			mv.lock.RUnlock()
		} else {
			mw.writers = append(mw.writers, o)
		}
	}
}

func (mw *multiWriter) Remove(out ...io.Writer) {
	if len(out) == 0 {
		return
	}
	mw.lock.Lock()
	defer mw.lock.Unlock()

	writers := make([]io.Writer, 0, len(mw.writers))
	for _, w := range mw.writers {
		var remove bool
		for _, o := range out {
			if w == o {
				remove = true
				break
			}
			if mv, ok := o.(*multiWriter); ok {
				mv.lock.RLock()
				if remove = contains(mv.writers, w); remove {
					mv.lock.RUnlock()
					break
				}
				mv.lock.RUnlock()
			}
		}
		if !remove {
			writers = append(writers, w)
		}
	}
	mw.writers = writers
}

func (mw *multiWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	mw.lock.RLock()
	defer mw.lock.RUnlock()

	for _, w := range mw.writers {
		nn, wErr := w.Write(p)
		if err == nil && wErr != nil {
			err = wErr
			n = nn
		}
		if err == nil && nn != len(p) {
			err = io.ErrShortWrite
			n = nn
		}
	}
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func (mw *multiWriter) WriteString(s string) (n int, err error) {
	if len(s) == 0 {
		return 0, nil
	}
	mw.lock.RLock()
	defer mw.lock.RUnlock()

	var p []byte // Only alloc if one writer does not implement io.StringWriter.
	for _, w := range mw.writers {
		var (
			nn   int
			wErr error
		)
		if sw, ok := w.(io.StringWriter); ok {
			nn, wErr = sw.WriteString(s)
		} else {
			if p == nil {
				p = []byte(s)
			}
			nn, wErr = w.Write(p)
		}
		if err == nil && wErr != nil {
			err = wErr
			n = nn
		}
		if err == nil && nn != len(s) {
			err = io.ErrShortWrite
			n = nn
		}
	}
	if err != nil {
		return n, err
	}
	return len(s), nil
}

func contains(writers []io.Writer, w io.Writer) bool {
	for _, v := range writers {
		if v == w {
			return true
		}
	}
	return false
}
