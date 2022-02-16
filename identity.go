// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"encoding/json"
	"errors"
	"io"
	"time"
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

// IdentityInfo describes a KES identity.
type IdentityInfo struct {
	Identity  Identity  `json:"identity"`
	Policy    string    `json:"policy"`     // Name of the associated policy
	CreatedAt time.Time `json:"created_at"` // Point in time when the identity was created
	CreatedBy Identity  `json:"created_by"` // Identity that created the identity
}

// IdentityIterator iterates over a stream of IdentityInfo objects.
// Close the IdentityIterator to release associated resources.
type IdentityIterator struct {
	decoder *json.Decoder
	closer  io.Closer

	current IdentityInfo
	err     error
	closed  bool
}

// Value returns the current IdentityInfo. It remains valid
// until Next is called again.
func (i *IdentityIterator) Value() IdentityInfo { return i.current }

// Identity returns the current identity. It is a short-hand
// for Value().Identity.
func (i *IdentityIterator) Identity() Identity { return i.current.Identity }

// Policy returns the policy assigned to the current identity.
// It is a short-hand for Value().Policy.
func (i *IdentityIterator) Policy() string { return i.current.Policy }

// CreatedAt returns the created-at timestamp of the current
// identity. It is a short-hand for Value().CreatedAt.
func (i *IdentityIterator) CreatedAt() time.Time { return i.current.CreatedAt }

// CreatedBy returns the identiy that created the current identity.
// It is a short-hand for Value().CreatedBy.
func (i *IdentityIterator) CreatedBy() Identity { return i.current.CreatedBy }

// Next returns true if there is another IdentityInfo.
// It returns false if there are no more IdentityInfo
// objects or when the IdentityIterator encounters an
// error.
func (i *IdentityIterator) Next() bool {
	type Response struct {
		Identity  Identity  `json:"identity"`
		Policy    string    `json:"policy"`
		CreatedAt time.Time `json:"created_at"`
		CreatedBy Identity  `json:"created_by"`

		Err string `json:"error"`
	}

	if i.closed || i.err != nil {
		return false
	}
	var resp Response
	if err := i.decoder.Decode(&resp); err != nil {
		if errors.Is(err, io.EOF) {
			i.err = i.Close()
		} else {
			i.err = err
		}
		return false
	}
	if resp.Err != "" {
		i.err = errors.New(resp.Err)
		return false
	}

	i.current = IdentityInfo{
		Identity:  resp.Identity,
		Policy:    resp.Policy,
		CreatedAt: resp.CreatedAt,
		CreatedBy: resp.CreatedBy,
	}
	return true
}

// Close closes the IdentityIterator and releases
// any associated resources
func (i *IdentityIterator) Close() error {
	if !i.closed {
		err := i.closer.Close()
		if i.err == nil {
			i.err = err
		}
		i.closed = true
		return err
	}
	return i.err
}
