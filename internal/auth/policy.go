// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"context"
	"net/http"
	"path"
	"time"

	"github.com/minio/kes-go"
)

// A PolicySet is a set of policies.
type PolicySet interface {
	// Set creates or replaces the policy at the given name.
	Set(ctx context.Context, name string, policy *Policy) error

	// Get returns the policy with the given name.
	//
	// It returns ErrPolicyNotFound if no policy with
	// the given name exists.
	Get(ctx context.Context, name string) (*Policy, error)

	// Delete deletes the policy with the given name.
	//
	// It returns ErrPolicyNotFound if no policy with
	// the given name exists.
	Delete(ctx context.Context, name string) error

	// List returns an iterator over all policies.
	List(ctx context.Context) (PolicyIterator, error)
}

// A PolicyIterator iterates over a list of policies.
//
//	for iterator.Next() {
//	    _ = iterator.Name() // Get the next policy
//	}
//	if err := iterator.Close(); err != nil {
//	}
//
// Once done iterating, a PolicyIterator should be closed.
//
// In general, a PolicyIterator does not provide any
// ordering guranatees. Concurrent changes to the
// underlying source may not be reflected by the iterator.
type PolicyIterator interface {
	// Next moves the iterator to the subsequent policy, if any.
	// This policy is available until Next is called again.
	//
	// It returns true if and only if there is another policy.
	// Once an error occurs or once there are no more policies,
	// Next returns false.
	Next() bool

	// Name returns the name of the current policy. Name can be
	// called multiple times and returns the same value until
	// Next is called again.
	Name() string

	// Close closes the iterator and releases resources. It
	// returns any error encountered while iterating, if any.
	// Otherwise, it returns any error that occurred while
	// closing, if any.
	Close() error
}

// A Policy defines whether an HTTP request is allowed or
// should be rejected.
//
// It contains a set of allow and deny rules that are
// matched against the URL path.
type Policy struct {
	// Allow is a list of glob patterns that are matched
	// against the URL path of incoming requests.
	Allow map[string]kes.Rule

	// Deny is a list of glob patterns that are matched
	// against the URL path of incoming requests.
	Deny map[string]kes.Rule

	// CreatedAt is the point in time when the policy
	// has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the policy.
	CreatedBy kes.Identity
}

// Verify reports whether the given HTTP request is allowed.
// It returns no error if:
//
//	(1) No deny pattern matches the URL path *AND*
//	(2) At least one allow pattern matches the URL path.
//
// Otherwise, Verify returns ErrNotAllowed.
func (p *Policy) Verify(r *http.Request) error {
	for pattern := range p.Deny {
		if ok, err := path.Match(pattern, r.URL.Path); ok && err == nil {
			return kes.ErrNotAllowed
		}
	}
	for pattern := range p.Allow {
		if ok, err := path.Match(pattern, r.URL.Path); ok && err == nil {
			return nil
		}
	}
	return kes.ErrNotAllowed
}
