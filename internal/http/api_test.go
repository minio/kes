// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import (
	"strings"
	"testing"
)

var validateNameTests = []struct {
	Name       string
	ShouldFail bool
}{
	{Name: "my-key"},                     // 0
	{Name: "0123456789"},                 // 1
	{Name: "MY-KEY"},                     // 2
	{Name: "MY-key-02"},                  // 3
	{Name: "02-my-KEY"},                  // 4
	{Name: "SomeVeryLongButAllowedName"}, // 5
	{Name: "_some-policy_"},              // 6
	{Name: "-_0-1-__1X-y"},               // 7

	{Name: "", ShouldFail: true},                      // 8
	{Name: "my-key,", ShouldFail: true},               // 9
	{Name: "my-key/xyz", ShouldFail: true},            // 10
	{Name: "C:my-key", ShouldFail: true},              // 11
	{Name: "/", ShouldFail: true},                     // 12
	{Name: ".", ShouldFail: true},                     // 13
	{Name: "..", ShouldFail: true},                    // 14
	{Name: "../../x", ShouldFail: true},               // 15
	{Name: "\\", ShouldFail: true},                    // 16
	{Name: "\\..\\x", ShouldFail: true},               // 17
	{Name: "[", ShouldFail: true},                     // 18
	{Name: "]", ShouldFail: true},                     // 19
	{Name: "?", ShouldFail: true},                     // 20
	{Name: strings.Repeat("a", 81), ShouldFail: true}, // 21
}

func TestValidateName(t *testing.T) {
	for i, test := range validateNameTests {
		if test.ShouldFail {
			if err := validateName(test.Name); err == nil {
				t.Fatalf("Test %d: should fail but succeeded", i)
			}
		} else {
			if err := validateName(test.Name); err != nil {
				t.Fatalf("Test %d: should pass but failed: %v", i, err)
			}
		}
	}
}

var validatePatternTests = []struct {
	Pattern    string
	ShouldFail bool
}{
	{Pattern: "my-key"},                        // 0
	{Pattern: "0123456789"},                    // 1
	{Pattern: "MY-KEY"},                        // 2
	{Pattern: "MY-key-02"},                     // 3
	{Pattern: "02-my-KEY"},                     // 4
	{Pattern: "SomeVeryLongButAllowedPattern"}, // 5
	{Pattern: "_some-policy_"},                 // 6
	{Pattern: "-_0-1-__1X-y"},                  // 7
	{Pattern: "my-key*"},                       // 8
	{Pattern: "*"},                             // 9
	{Pattern: "*my-key"},                       // 10
	{Pattern: "**"},                            // 11
	{Pattern: "*my-key*"},                      // 12

	{Pattern: "", ShouldFail: true},                      // 13
	{Pattern: "my-key,", ShouldFail: true},               // 14
	{Pattern: "my-key/xyz", ShouldFail: true},            // 15
	{Pattern: "C:my-key", ShouldFail: true},              // 16
	{Pattern: "/", ShouldFail: true},                     // 17
	{Pattern: ".", ShouldFail: true},                     // 18
	{Pattern: "..", ShouldFail: true},                    // 19
	{Pattern: "../../x", ShouldFail: true},               // 20
	{Pattern: "\\", ShouldFail: true},                    // 21
	{Pattern: "\\..\\x", ShouldFail: true},               // 22
	{Pattern: "[", ShouldFail: true},                     // 23
	{Pattern: "]", ShouldFail: true},                     // 24
	{Pattern: "?", ShouldFail: true},                     // 25
	{Pattern: strings.Repeat("a", 81), ShouldFail: true}, // 26
}

func TestValidatePattern(t *testing.T) {
	for i, test := range validatePatternTests {
		if test.ShouldFail {
			if err := validatePattern(test.Pattern); err == nil {
				t.Fatalf("Test %d: should fail but succeeded", i)
			}
		} else {
			if err := validatePattern(test.Pattern); err != nil {
				t.Fatalf("Test %d: should pass but failed: %v", i, err)
			}
		}
	}
}
