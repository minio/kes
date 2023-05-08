// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kv

// An Iter traverses a list of elements.
//
// Its Next method returns the next
// element as long as there is one.
//
// Closing an Iter causes Next to return
// false and releases associated resources.
//
// A common use of an Iter is a for loop:
//
//	 for v, ok := iter.Next(); ok; v, ok = iter.Next() {
//	    _ = v
//	 }
//	 if err := iter.Close() {
//	    // release resources and handle potential errors
//	}
type Iter[T any] interface {
	// Next returns the next element, if any,
	// and reports whether there may be more
	// elements (true) or whether the end of
	// the Iter has been reached (false).
	//
	// Once Next returns false, Close returns
	// the first error encountered, if any.
	Next() (T, bool)

	// Close stops the Iter and releases
	// associated resources.
	//
	// Once closed, Next no longer returns
	// elements but reports false.
	Close() error
}
