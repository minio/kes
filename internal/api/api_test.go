// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package api

import (
	"net/url"
	"strings"
	"testing"
)

func TestVerifyName(t *testing.T) {
	for i, test := range verifyNameTests {
		err := verifyName(test.Name)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: name '%s' is valid but got rejected: %v", i, test.Name, err)
		}
	}
}

func TestPatternName(t *testing.T) {
	for i, test := range verifyPatternTests {
		err := verifyPattern(test.Pattern)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: pattern '%s' is valid but got rejected: %v", i, test.Pattern, err)
		}
	}
}

func TestNameFromRequest(t *testing.T) {
	for i, test := range nameFromRequestTests {
		url, err := url.Parse(test.URL)
		if err != nil {
			t.Fatalf("Test %d: failed to parse URL '%s': %v", i, test.URL, err)
		}

		name, err := trimPath(url, test.Path, IsValidName)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to get name from request: %v", i, err)
		}
		if err == nil && name != test.Name {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, name, test.Name)
		}
	}
}

func TestPatternFromRequest(t *testing.T) {
	for i, test := range patternFromRequestTests {
		url, err := url.Parse(test.URL)
		if err != nil {
			t.Fatalf("Test %d: failed to parse URL '%s': %v", i, test.URL, err)
		}

		pattern, err := trimPath(url, test.Path, IsValidPattern)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to get name from request: %v", i, err)
		}
		if err == nil && pattern != test.Pattern {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, pattern, test.Pattern)
		}
	}
}

var (
	verifyNameTests = []struct {
		Name       string
		ShouldFail bool
	}{
		{Name: "my-key"},    // 0
		{Name: "abc123"},    // 1
		{Name: "0"},         // 2
		{Name: "123ABC321"}, // 3
		{Name: "_-___---_"}, // 4
		{Name: "_0"},        // 5
		{Name: "0-Z"},       // 6
		{Name: "my_key-0"},  // 7

		{Name: "", ShouldFail: true},                      // 8
		{Name: "my.key", ShouldFail: true},                // 9
		{Name: "key/", ShouldFail: true},                  // 10
		{Name: "", ShouldFail: true},                      // 11
		{Name: "☰", ShouldFail: true},                     // 12
		{Name: "hel<lo", ShouldFail: true},                // 13
		{Name: "Εmacs", ShouldFail: true},                 // 14 - greek Ε
		{Name: strings.Repeat("a", 81), ShouldFail: true}, // 15
	}

	verifyPatternTests = []struct {
		Pattern    string
		ShouldFail bool
	}{
		{Pattern: "my-key"},    // 0
		{Pattern: "abc123"},    // 1
		{Pattern: "0"},         // 2
		{Pattern: "123ABC321"}, // 3
		{Pattern: "_-___---_"}, // 4
		{Pattern: "_0"},        // 5
		{Pattern: "0-Z"},       // 6
		{Pattern: "*"},         // 7
		{Pattern: "my*"},       // 8
		{Pattern: "_-*"},       // 9
		{Pattern: "*-*"},       // 10

		{Pattern: "", ShouldFail: true},                      // 11
		{Pattern: "my.key", ShouldFail: true},                // 12
		{Pattern: "key/", ShouldFail: true},                  // 13
		{Pattern: "", ShouldFail: true},                      // 14
		{Pattern: "☰", ShouldFail: true},                     // 15
		{Pattern: "hel<lo", ShouldFail: true},                // 16
		{Pattern: "Εmacs", ShouldFail: true},                 // 17 - greek Ε
		{Pattern: strings.Repeat("a", 81), ShouldFail: true}, // 18
	}

	nameFromRequestTests = []struct {
		URL        string
		Path       string
		Name       string
		ShouldFail bool
	}{
		{ // 0
			URL:  "https://localhost:7373/v1/key/create/my-key",
			Path: "/v1/key/create/", Name: "my-key",
		},
		{ // 1
			URL:  "https://127.0.0.1:4433/v1/policy/read/my-policy",
			Path: "/v1/policy/read/", Name: "my-policy",
		},
		{ // 2
			URL:  "https://localhost:7373/version",
			Path: "/version", ShouldFail: true,
		},
		{ // 3
			URL:  "https://localhost:7373/v1/policy/read/my-policy",
			Path: "/v1/key/create/", ShouldFail: true,
		},
		{ // 4
			URL:  "https://localhost:7373/key/create/my.key",
			Path: "/v1/key/create/", ShouldFail: true,
		},
		{ // 5
			URL:  "https://localhost:7373/key/create/my/key",
			Path: "/v1/key/create/", ShouldFail: true,
		},
		{ // 6
			URL:  "https://localhost:7373/key/create/my*",
			Path: "/v1/key/create/", ShouldFail: true,
		},
	}

	patternFromRequestTests = []struct {
		URL        string
		Path       string
		Pattern    string
		ShouldFail bool
	}{
		{ // 0
			URL:  "https://localhost:7373/v1/key/list/*",
			Path: "/v1/key/list/", Pattern: "*",
		},
		{ // 1
			URL:  "https://127.0.0.1:4433/v1/policy/read/my-*",
			Path: "/v1/policy/read/", Pattern: "my-*",
		},
		{ // 2
			URL:  "https://localhost:7373/version",
			Path: "/version", ShouldFail: true,
		},
		{ // 3
			URL:  "https://localhost:7373/v1/policy/read/my-policy",
			Path: "/v1/key/create/", ShouldFail: true,
		},
		{ // 4
			URL:  "https://localhost:7373/key/create/my.key",
			Path: "/v1/key/create/", ShouldFail: true,
		},
		{ // 5
			URL:  "https://localhost:7373/key/create/my/key",
			Path: "/v1/key/create/", ShouldFail: true,
		},
	}
)
