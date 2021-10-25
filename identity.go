// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"io"
	"net/http"
)

// IdentityUnknown is the identity returned
// by an IdentityFunc if it cannot map a
// particular X.509 certificate to an actual
// identity.
const IdentityUnknown Identity = ""

// An Identity should uniquely identify a client and
// is computed from the X.509 certificate presented
// by the client during the TLS handshake using an
// IdentityFunc.
type Identity string

// IsUnknown returns true if and only if the
// identity is IdentityUnknown.
func (id Identity) IsUnknown() bool { return id == IdentityUnknown }

// String returns the string representation of
// the identity.
func (id Identity) String() string { return string(id) }

// IdentityIterator iterates over list of IdentityDescription objects.
//   for iterator.Next() {
//       _ = iterator.Value() // Use the IdentityDescription
//   }
//   if err := iterator.Err(); err != nil {
//   }
//   if err := iterator.Close(); err != nil {
//   }
//
// Once done with iterating over the list of IdentityDescription
// objects, an iterator should be closed using the Close
// method.
//
// In general, an IdentityIterator does not provide any guarantees
// about ordering or the when its underlying source is modified
// concurrently.
// Particularly, if an identity is created or deleted at the KES server
// the IdentityIterator may or may not be affected by this change.
type IdentityIterator struct {
	response *http.Response
	decoder  *json.Decoder

	last     IdentityDescription
	nextErr  error // error encountered in Next()
	closeErr error // error encountered in Close()
	closed   bool
}

// IdentityDescription describes an identity at a KES server.
type IdentityDescription struct {
	Identity Identity `json:"identity"`
	Policy   string   `json:"policy"`
}

// Next returns true if there is another IdentityDescription.
// This IdentityDescription can be retrieved via the Value method.
//
// It returns false once there are no more IdentityDescriptions
// or if the IdentityIterator encountered an error. The error,
// if any, can beretrieved via the Err method.
func (i *IdentityIterator) Next() bool {
	if i.closed || i.nextErr != nil {
		return false
	}
	if err := i.decoder.Decode(&i.last); err != nil {
		if err == io.EOF {
			i.nextErr = i.Close()
		} else {
			i.nextErr = err
		}
		return false
	}
	return true
}

// Value returns the current IdentityDescription. It returns
// the same IdentityDescription until Next is called again.
//
// If the IdentityIterator has been closed or if Next has not
// been called once resp. Next returns false then the behavior
// of Value is undefined.
func (i *IdentityIterator) Value() IdentityDescription { return i.last }

// Err returns the first error encountered by the IdentityIterator,
// if any.
func (i *IdentityIterator) Err() error { return i.nextErr }

// Close closes the underlying connection to the KES server and
// returns any encountered error.
func (i *IdentityIterator) Close() error {
	if !i.closed {
		i.closed = true
		if err := i.response.Body.Close(); err != nil {
			i.closeErr = err
		}
		if err := parseErrorTrailer(i.response.Trailer); err != nil && i.closeErr == nil {
			i.closeErr = err
		}
	}
	return i.closeErr
}
