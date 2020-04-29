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
	{
		Policy: mustNewPolicy(),
		Output: `{"paths":[]}`,
	},
	{
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*"),
		Output: `{"paths":["/v1/key/create/*","/v1/key/delete/*"]}`,
	},
	{
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Output: `{"paths":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"]}`,
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
		Source: `{"paths":null}`,
		Policy: mustNewPolicy(),
		Err:    nil,
	},
	{ // 1
		Source: `{"paths":[]}`,
		Policy: mustNewPolicy(),
		Err:    nil,
	},
	{ // 2
		Source: `{"paths":[""]}`,
		Policy: mustNewPolicy(""),
		Err:    nil,
	},
	{ // 3
		Source: `{"paths":["/v1/key/create/*","/v1/key/delete/*"]}`,
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*"),
		Err:    nil,
	},
	{ // 4
		Source: `{"paths":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key"]}`,
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Err:    nil,
	},
	{ // 5
		Source: `{"paths":["/v1/key/create/*","/v1/key/delete/*","/v1/key/generate/my-key\\"]}`,
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
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
			if len(policy.patterns) != len(test.Policy.patterns) {
				t.Fatalf("Test %d: policy differs in paths: got %d - want %d", i, len(policy.patterns), len(test.Policy.patterns))
			}

			sort.Strings(policy.patterns)
			sort.Strings(test.Policy.patterns)
			for j := range policy.patterns {
				if policy.patterns[j] != test.Policy.patterns[j] {
					t.Fatalf("Test %d: policy path %d does not match: got %s - want %s", i, j, policy.patterns[j], test.Policy.patterns[j])
				}
			}
		}
	}
}

var policyStringTests = []struct {
	Policy *Policy
	Output string
}{
	{ // 0
		Policy: mustNewPolicy(),
		Output: "[\n]\n",
	},
	{ // 1
		Policy: mustNewPolicy(""),
		Output: "[\n]\n",
	},
	{ // 2
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*"),
		Output: "[\n  /v1/key/create/*\n  /v1/key/delete/*\n]\n",
	},
	{ // 3
		Policy: mustNewPolicy("/v1/key/create/*", "/v1/key/delete/*", "/v1/key/generate/my-key"),
		Output: "[\n  /v1/key/create/*\n  /v1/key/delete/*\n  /v1/key/generate/my-key\n]\n",
	},
}

func TestPolicyString(t *testing.T) {
	for i, test := range policyStringTests {
		output := test.Policy.String()
		if output != test.Output {
			t.Fatalf("Test %d: got %s - want %s", i, output, test.Output)
		}
	}
}

var policyVerifyTests = []struct {
	Pattern     string
	Path        string
	ShouldMatch bool
}{
	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/my-key", ShouldMatch: true},                      // 0
	{Pattern: "/v1/key/import/*", Path: "/v1/key/import/my-key", ShouldMatch: true},                      // 1
	{Pattern: "/v1/key/delete/*", Path: "/v1/key/delete/my-key", ShouldMatch: true},                      // 2
	{Pattern: "/v1/key/generate/*", Path: "/v1/key/generate/my-key", ShouldMatch: true},                  // 3
	{Pattern: "/v1/key/decrypt/*", Path: "/v1/key/decrypt/my-key", ShouldMatch: true},                    // 4
	{Pattern: "/v1/policy/write/*", Path: "/v1/policy/write/my-policy", ShouldMatch: true},               // 5
	{Pattern: "/v1/policy/read/*", Path: "/v1/policy/read/my-policy", ShouldMatch: true},                 // 6
	{Pattern: "/v1/policy/list/*", Path: "/v1/policy/list/my-policy", ShouldMatch: true},                 // 7
	{Pattern: "/v1/policy/list/*", Path: "/v1/policy/list/*", ShouldMatch: true},                         // 8
	{Pattern: "/v1/policy/delete/*", Path: "/v1/policy/delete/my-policy", ShouldMatch: true},             // 9
	{Pattern: "/v1/identity/assign/*/*", Path: "/v1/identity/assign/af43c/my-policy", ShouldMatch: true}, // 10
	{Pattern: "/v1/identity/list/*", Path: "/v1/identity/list/af43c", ShouldMatch: true},                 // 11
	{Pattern: "/v1/identity/list/*", Path: "/v1/identity/list/*", ShouldMatch: true},                     // 12
	{Pattern: "/v1/identity/forget/*", Path: "/v1/identity/forget/af43c", ShouldMatch: true},             // 13
	{Pattern: "/v1/log/audit/trace", Path: "/v1/log/audit/trace", ShouldMatch: true},                     // 14

	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/my-key/..", ShouldMatch: false},   // 15
	{Pattern: "/v1/key/create/*", Path: "/v1/key/create/../my-key", ShouldMatch: false},   // 16
	{Pattern: "/v1/key/decypt/*", Path: "/v1/key/create/my-key", ShouldMatch: false},      // 17
	{Pattern: "/v1/key/generate/*", Path: "/v1/key/create/my-key/x", ShouldMatch: false},  // 18
	{Pattern: "/v1/key/create/[a-z]", Path: "/v1/key/create/my-key0", ShouldMatch: false}, // 19
	{Pattern: "/v1/key/decypt/*", Path: "/v1/key/create/./*/../a", ShouldMatch: false},    // 20
	{Pattern: "/v1/log/audit/trace", Path: "/v1/log/audit/trace/.", ShouldMatch: false},   // 21
}

func TestPolicyVerify(t *testing.T) {
	const baseURL = "https://localhost:7373"

	for i, test := range policyVerifyTests {
		policy, err := NewPolicy(test.Pattern)
		if err != nil {
			t.Fatalf("Test %d: failed to create policy: %v", i, err)
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

func mustNewPolicy(patterns ...string) *Policy {
	p, err := NewPolicy(patterns...)
	if err != nil {
		panic(err)
	}
	return p
}
