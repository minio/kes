// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"path"
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
	allowPatterns []string
	denyPatterns  []string
}

// NewPolicy returns a new policy that accepts requests
// if at least one of the given patterns matches the
// with request URL path. It returns an error if one
// of the patterns contains invalid glob syntax.
func NewPolicy(patterns ...string) (*Policy, error) {
	policy := new(Policy)
	if err := policy.Allow(patterns...); err != nil {
		return nil, err
	}
	return policy, nil
}

// Allow adds the given patterns to the list of
// allow rules. It ignores empty patterns and
// returns an error if one of the patterns contains
// invalid glob syntax.
func (p *Policy) Allow(patterns ...string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if _, err := path.Match(pattern, pattern); err != nil {
			return err
		}
		p.allowPatterns = append(p.allowPatterns, pattern)
	}
	return nil
}

// Deny adds the given patterns to the list of
// deny rules. It ignores empty patterns and
// returns an error if one of the patterns contains
// invalid glob syntax.
func (p *Policy) Deny(patterns ...string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if _, err := path.Match(pattern, pattern); err != nil {
			return err
		}
		p.denyPatterns = append(p.denyPatterns, pattern)
	}
	return nil
}

func (p Policy) MarshalJSON() ([]byte, error) {
	type PolicyJSON struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}

	policy := PolicyJSON{
		Allow: p.allowPatterns,
		Deny:  p.denyPatterns,
	}
	if len(policy.Allow) == 0 {
		policy.Allow = []string{} // marshal nil as empty array ([]) -  not null
	}
	if len(policy.Deny) == 0 {
		policy.Deny = []string{} // marshal nil as empty array ([]) -  not null
	}
	return json.Marshal(policy)
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()

	var policyJSON struct {
		Allow []string `json:"allow"`
		Deny  []string `json:"deny"`
	}
	if err := d.Decode(&policyJSON); err != nil {
		return err
	}

	deny := make([]string, 0, len(policyJSON.Deny))
	for _, pattern := range policyJSON.Deny {
		if pattern == "" {
			continue
		}
		if _, err := path.Match(pattern, pattern); err != nil {
			return err
		}
		deny = append(deny, pattern)
	}
	allow := make([]string, 0, len(policyJSON.Allow))
	for _, pattern := range policyJSON.Allow {
		if pattern == "" {
			continue
		}
		if _, err := path.Match(pattern, pattern); err != nil {
			return err
		}
		allow = append(allow, pattern)
	}
	p.allowPatterns, p.denyPatterns = allow, deny
	return nil
}

// Verify determines whether a request should be accepted
// or rejected. It returns ErrNotAllowed if any deny rule
// or no allow rule matches the given request.
func (p *Policy) Verify(r *http.Request) error {
	for _, pattern := range p.denyPatterns {
		if ok, _ := path.Match(pattern, r.URL.Path); ok {
			return ErrNotAllowed
		}
	}
	for _, pattern := range p.allowPatterns {
		if ok, _ := path.Match(pattern, r.URL.Path); ok {
			return nil
		}
	}
	return ErrNotAllowed
}
