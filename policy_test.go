// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"net/http"
	"path"
	"sort"
	"testing"
)

var newPolicyTests = []struct {
	Patterns []string
	Err      error
}{
	{ // 0
		Patterns: nil,
		Err:      nil,
	},
	{ // 1
		Patterns: []string{},
		Err:      nil,
	},
	{ // 2
		Patterns: []string{"/v1/key/generate/my-key"},
		Err:      nil,
	},
	{ // 3
		Patterns: []string{"/v1/key/generate/my-key", "/v1/identity/assign/*/a*"},
		Err:      nil,
	},
	{ // 4
		Patterns: []string{"/v1/key/generate/my-key-[a-]"},
		Err:      path.ErrBadPattern,
	},
	{ // 5
		Patterns: []string{"/v1/key/generate/my-key-\\"},
		Err:      path.ErrBadPattern,
	},
}

func TestNewPolicy(t *testing.T) {
	for i, test := range newPolicyTests {
		_, err := NewPolicy(test.Patterns...)
		if err != test.Err {
			t.Fatalf("Test %d: got error %v - want error: %v", i, err, test.Err)
		}
	}
}

var policyMarshalJSONTests = []struct {
	Policy *Policy
	Output string
}{
	{ // 0
		Policy: allowPolicy(),
		Output: `{"allow":[],"deny":[]}`,
	},
	{ // 1
		Policy: allowPolicy("/v1/key/create/*", "/v1/key/delete/*"),
		Output: `{"allow":["/v1/key/create/*","/v1/key/delete/*"],"deny":[]}`,
	},
	{ // 2
		Policy: allowPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Output: `{"allow":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"],"deny":[]}`,
	},
	{ // 3
		Policy: denyPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Output: `{"allow":[],"deny":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"]}`,
	},
}

func TestPolicyMarshalJSON(t *testing.T) {
	for i, test := range policyMarshalJSONTests {
		out, err := test.Policy.MarshalJSON()
		if err != nil {
			t.Fatalf("Test %d: %v", i, err)
		}

		output := string(out)
		if output != test.Output {
			t.Fatalf("Test %d: got %s - want %s", i, out, test.Output)
		}
	}
}

var policyUnmarshalJSONTests = []struct {
	Source string
	Policy *Policy
	Err    error
}{
	{ // 0
		Source: `{"allow":null}`,
		Policy: allowPolicy(),
		Err:    nil,
	},
	{ // 1
		Source: `{"allow":null,"deny":null}`,
		Policy: allowPolicy(),
		Err:    nil,
	},
	{ // 2
		Source: `{"allow":[]}`,
		Policy: allowPolicy(),
		Err:    nil,
	},
	{ // 3
		Source: `{"allow":[""]}`,
		Policy: allowPolicy(""),
		Err:    nil,
	},
	{ // 4
		Source: `{"allow":[""],"deny":[""]}`,
		Policy: allowPolicy(""),
		Err:    nil,
	},
	{ // 5
		Source: `{"allow":["/v1/key/create/*","/v1/key/delete/*"]}`,
		Policy: allowPolicy("/v1/key/create/*", "/v1/key/delete/*"),
		Err:    nil,
	},
	{ // 6
		Source: `{"allow":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"]}`,
		Policy: allowPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Err:    nil,
	},
	{ // 7
		Source: `{"allow":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key\\"]}`,
		Policy: allowPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Err:    path.ErrBadPattern,
	},
	{ // 8
		Source: `{"deny":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"]}`,
		Policy: denyPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Err:    nil,
	},
	{ // 9
		Source: `{"deny":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key\\"]}`,
		Policy: denyPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Err:    path.ErrBadPattern,
	},
}

func TestPolicyUnmarshalJSON(t *testing.T) {
	for i, test := range policyUnmarshalJSONTests {
		var policy Policy
		err := policy.UnmarshalJSON([]byte(test.Source))
		if err != test.Err {
			t.Fatalf("Test %d: got error %v - want error: %v", i, err, test.Err)
		}
		if err == nil {
			if len(policy.allowPatterns) != len(test.Policy.allowPatterns) {
				t.Fatalf("Test %d: policy differs in paths: got %d - want %d", i, len(policy.allowPatterns), len(test.Policy.allowPatterns))
			}

			sort.Strings(policy.allowPatterns)
			sort.Strings(test.Policy.allowPatterns)
			for j := range policy.allowPatterns {
				if policy.allowPatterns[j] != test.Policy.allowPatterns[j] {
					t.Fatalf("Test %d: policy path %d does not match: got %s - want %s", i, j, policy.allowPatterns[j], test.Policy.allowPatterns[j])
				}
			}
		}
	}
}

var policyVerifyTests = []struct {
	Allow       string
	Deny        string
	Path        string
	ShouldMatch bool
}{
	{Allow: "/v1/key/create/*", Path: "/v1/key/create/my-key", ShouldMatch: true},                      // 0
	{Allow: "/v1/key/import/*", Path: "/v1/key/import/my-key", ShouldMatch: true},                      // 1
	{Allow: "/v1/key/delete/*", Path: "/v1/key/delete/my-key", ShouldMatch: true},                      // 2
	{Allow: "/v1/key/generate/*", Path: "/v1/key/generate/my-key", ShouldMatch: true},                  // 3
	{Allow: "/v1/key/decrypt/*", Path: "/v1/key/decrypt/my-key", ShouldMatch: true},                    // 4
	{Allow: "/v1/policy/write/*", Path: "/v1/policy/write/my-policy", ShouldMatch: true},               // 5
	{Allow: "/v1/policy/read/*", Path: "/v1/policy/read/my-policy", ShouldMatch: true},                 // 6
	{Allow: "/v1/policy/list/*", Path: "/v1/policy/list/my-policy", ShouldMatch: true},                 // 7
	{Allow: "/v1/policy/list/*", Path: "/v1/policy/list/*", ShouldMatch: true},                         // 8
	{Allow: "/v1/policy/delete/*", Path: "/v1/policy/delete/my-policy", ShouldMatch: true},             // 9
	{Allow: "/v1/identity/assign/*/*", Path: "/v1/identity/assign/af43c/my-policy", ShouldMatch: true}, // 10
	{Allow: "/v1/identity/list/*", Path: "/v1/identity/list/af43c", ShouldMatch: true},                 // 11
	{Allow: "/v1/identity/list/*", Path: "/v1/identity/list/*", ShouldMatch: true},                     // 12
	{Allow: "/v1/identity/forget/*", Path: "/v1/identity/forget/af43c", ShouldMatch: true},             // 13
	{Allow: "/v1/log/audit/trace", Path: "/v1/log/audit/trace", ShouldMatch: true},                     // 14

	{Deny: "/v1/key/create/*", Path: "/v1/key/create/my-key", ShouldMatch: false},                      // 15
	{Deny: "/v1/key/import/*", Path: "/v1/key/import/my-key", ShouldMatch: false},                      // 16
	{Deny: "/v1/key/delete/*", Path: "/v1/key/delete/my-key", ShouldMatch: false},                      // 17
	{Deny: "/v1/key/generate/*", Path: "/v1/key/generate/my-key", ShouldMatch: false},                  // 18
	{Deny: "/v1/key/decrypt/*", Path: "/v1/key/decrypt/my-key", ShouldMatch: false},                    // 19
	{Deny: "/v1/policy/write/*", Path: "/v1/policy/write/my-policy", ShouldMatch: false},               // 20
	{Deny: "/v1/policy/read/*", Path: "/v1/policy/read/my-policy", ShouldMatch: false},                 // 21
	{Deny: "/v1/policy/list/*", Path: "/v1/policy/list/my-policy", ShouldMatch: false},                 // 22
	{Deny: "/v1/policy/list/*", Path: "/v1/policy/list/*", ShouldMatch: false},                         // 23
	{Deny: "/v1/policy/delete/*", Path: "/v1/policy/delete/my-policy", ShouldMatch: false},             // 24
	{Deny: "/v1/identity/assign/*/*", Path: "/v1/identity/assign/af43c/my-policy", ShouldMatch: false}, // 25
	{Deny: "/v1/identity/list/*", Path: "/v1/identity/list/af43c", ShouldMatch: false},                 // 26
	{Deny: "/v1/identity/list/*", Path: "/v1/identity/list/*", ShouldMatch: false},                     // 27
	{Deny: "/v1/identity/forget/*", Path: "/v1/identity/forget/af43c", ShouldMatch: false},             // 28
	{Deny: "/v1/log/audit/trace", Path: "/v1/log/audit/trace", ShouldMatch: false},                     // 29

	{Allow: "/v1/key/create/*", Path: "/v1/key/create/my-key/..", ShouldMatch: false},   // 30
	{Allow: "/v1/key/create/*", Path: "/v1/key/create/../my-key", ShouldMatch: false},   // 31
	{Allow: "/v1/key/decypt/*", Path: "/v1/key/create/my-key", ShouldMatch: false},      // 32
	{Allow: "/v1/key/generate/*", Path: "/v1/key/create/my-key/x", ShouldMatch: false},  // 33
	{Allow: "/v1/key/create/[a-z]", Path: "/v1/key/create/my-key0", ShouldMatch: false}, // 34
	{Allow: "/v1/key/decypt/*", Path: "/v1/key/create/./*/../a", ShouldMatch: false},    // 35
	{Allow: "/v1/log/audit/trace", Path: "/v1/log/audit/trace/.", ShouldMatch: false},   // 36
}

func TestPolicyVerify(t *testing.T) {
	const baseURL = "https://localhost:7373"

	for i, test := range policyVerifyTests {
		policy, err := NewPolicy()
		if err != nil {
			t.Fatalf("Test %d: failed to create policy: %v", i, err)
		}
		if err = policy.Allow(test.Allow); err != nil {
			t.Fatalf("Test %d: failed to add allow pattern: %v", i, err)
		}
		if err = policy.Deny(test.Deny); err != nil {
			t.Fatalf("Test %d: failed to add deny pattern: %v", i, err)
		}

		req, err := http.NewRequest(http.MethodGet, baseURL+test.Path, nil)
		if err != nil {
			t.Fatalf("Test %d: failed to create request: %v", i, err)
		}

		err = policy.Verify(req)
		if err != nil && test.ShouldMatch {
			t.Fatalf("Test %d: path should have matched pattern - but got: %v", i, err)
		}
		if err != ErrNotAllowed && !test.ShouldMatch {
			t.Fatalf("Test %d: path should not have matched pattern: got %v - want %v", i, err, ErrNotAllowed)
		}
	}
}

func allowPolicy(patterns ...string) *Policy {
	p, err := NewPolicy(patterns...)
	if err != nil {
		panic(err)
	}
	return p
}

func denyPolicy(patterns ...string) *Policy {
	p, err := NewPolicy()
	if err != nil {
		panic(err)
	}
	p.Deny(patterns...)
	return p
}
