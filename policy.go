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

// Policy contains a set of rules that explicitly allow
// or deny HTTP requests.
//
// These rules are specified as glob patterns. The rule
// applies if the pattern matches the request URL path.
// For more details on the glob syntax in general see [1]
// and for the specific pattern syntax see [2].
//
// A policy contains two different rule sets:
//   • Allow rules
//   • Deny  rules
//
// A policy determines whether a request should be allowed
// or denied in two steps. First, it iterates over all deny
// rules. If any deny rules matches the given request then
// the request is rejected. Then it iterates over all
// allow rules. If any allow rule matches the given request
// then the request is accepted. Otherwise, the request
// is rejected by default.
// Hence, a request is only accepted if at least one allow
// rules and no deny rule matches the request. Also, a deny
// rule takes precedence over an allow rule.
//
// [1]: https://en.wikipedia.org/wiki/Glob_(programming)
// [2]: https://golang.org/pkg/path/#Match
type Policy struct {
	Allow []string // Set of allow patterns
	Deny  []string // Set of deny patterns

	Info PolicyInfo // Info contains metadata for the Policy.
}

// PolicyInfo describes a KES policy.
type PolicyInfo struct {
	Name      string    `json:"name"`                 // Name of the policy
	CreatedAt time.Time `json:"created_at,omitempty"` // Point in time when the policy was created
	CreatedBy Identity  `json:"created_by,omitempty"` // Identity that created the policy
}

// PolicyIterator iterates over a stream of PolicyInfo objects.
// Close the PolicyIterator to release associated resources.
type PolicyIterator struct {
	decoder *json.Decoder
	closer  io.Closer

	current PolicyInfo
	err     error
	closed  bool
}

// Value returns the current PolicyInfo. It remains valid
// until Next is called again.
func (i *PolicyIterator) Value() PolicyInfo { return i.current }

// Name returns the name of the current policy.
// It is a short-hand for Value().Name.
func (i *PolicyIterator) Name() string { return i.current.Name }

// CreatedAt returns the created at timestamp of the current
// policy. It is a short-hand for Value().CreatedAt.
func (i *PolicyIterator) CreatedAt() time.Time { return i.current.CreatedAt }

// CreatedBy returns the identiy that created the current policy.
// It is a short-hand for Value().CreatedBy.
func (i *PolicyIterator) CreatedBy() Identity { return i.current.CreatedBy }

// Next returns true if there is another PolicyInfo.
// It returns false if there are no more PolicyInfo
// objects or when the PolicyIterator encounters an
// error.
func (i *PolicyIterator) Next() bool {
	type Response struct {
		Name      string    `json:"name"`
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

	i.current = PolicyInfo{
		Name:      resp.Name,
		CreatedAt: resp.CreatedAt,
		CreatedBy: resp.CreatedBy,
	}
	return true
}

// WriteTo encodes and writes all remaining PolicyInfos
// from its current iterator position to w. It returns
// the number of bytes written to w and the first error
// encounterred, if any.
func (i *PolicyIterator) WriteTo(w io.Writer) (int64, error) {
	type Response struct {
		Name      string    `json:"name"`
		CreatedAt time.Time `json:"created_at,omitempty"`
		CreatedBy Identity  `json:"created_by,omitempty"`

		Err string `json:"error,omitempty"`
	}
	if i.err != nil {
		return 0, i.err
	}
	if i.closed {
		return 0, errors.New("kes: WriteTo called after Close")
	}

	cw := countWriter{W: w}
	encoder := json.NewEncoder(&cw)
	for {
		var resp Response
		if err := i.decoder.Decode(&resp); err != nil {
			if errors.Is(err, io.EOF) {
				i.err = i.Close()
			} else {
				i.err = err
			}
			return cw.N, i.err
		}
		if resp.Err != "" {
			i.err = errors.New(resp.Err)
			return cw.N, i.err
		}
		if err := encoder.Encode(resp); err != nil {
			i.err = err
			return cw.N, err
		}
	}
}

// Close closes the PolicyIterator and releases
// any associated resources.
func (i *PolicyIterator) Close() error {
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
