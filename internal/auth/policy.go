// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/msgp"
)

type Rule = struct{}

// A Policy defines whether an HTTP request is allowed or
// should be rejected.
//
// It contains a set of allow and deny rules that are
// matched against the URL path.
type Policy struct {
	// Allow is a list of glob patterns that are matched
	// against the URL path of incoming requests.
	Allow map[string]Rule

	// Deny is a list of glob patterns that are matched
	// against the URL path of incoming requests.
	Deny map[string]Rule

	// CreatedAt is the point in time when the policy
	// has been created.
	CreatedAt time.Time

	// CreatedBy is the identity that created the policy.
	CreatedBy kes.Identity
}

func (p *Policy) MarshalMsg() (msgp.Policy, error) {
	return msgp.Policy{
		Allow:     p.Allow,
		Deny:      p.Deny,
		CreatedAt: p.CreatedAt,
		CreatedBy: p.CreatedBy.String(),
	}, nil
}

func (p *Policy) UnmarshalMsg(v *msgp.Policy) error {
	p.Allow = v.Allow
	p.Deny = v.Deny
	p.CreatedAt = v.CreatedAt
	p.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
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
		if match(r.URL.Path, pattern) {
			return kes.ErrNotAllowed
		}
	}
	for pattern := range p.Allow {
		if match(r.URL.Path, pattern) {
			return nil
		}
	}
	return kes.ErrNotAllowed
}

// IsSubset reports whether the Policy p is a subset of o.
// If it is then any request allowed by p is also allowed
// by o and any request rejected by o is also rejected by p.
//
// Usually, a Policy p is a subset of o when it contains
// less or less generic allow rules and/or more or more
// generic deny rules.
//
// Two policies, A and B, are equivalent, but not necessarily
// equal, if:
//
//	A.IsSubset(B) && B.IsSubset(A)
func (p *Policy) IsSubset(o *Policy) bool {
	for allow := range p.Allow {

		// First, we check whether p's allow rule set
		// is a subset of o's allow rule set.
		var matched bool
		for pattern := range o.Allow {
			if matched = match(pattern, allow); matched {
				break
			}
		}
		if !matched {
			return false
		}

		// Next, we check whether one of p's allow rules
		// matches any of o's deny rules. If so, p would
		// allow something o denies unless p also contains
		// a deny rule equal or more generic than o's.
		for super := range o.Deny {
			if !match(allow, super) {
				continue
			}

			matched = false
			for deny := range p.Deny {
				if matched = match(deny, super); matched {
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	return true
}

func match(pattern, s string) bool {
	if pattern == "" {
		return false
	}

	if i := len(pattern) - 1; pattern[i] == '*' {
		return strings.HasPrefix(s, pattern[:i])
	}
	return s == pattern
}
