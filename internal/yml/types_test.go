// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

import (
	"os"
	"testing"
)

func TestReplace(t *testing.T) {
	for i, test := range replaceTests {
		value := replace(test.Value, test.Mapping)
		if value != test.Result {
			t.Fatalf("Test %d: got %q - want %q", i, value, test.Result)
		}
	}
}

var replaceTests = []struct {
	Value   string
	Mapping func(string) string
	Result  string
}{
	{ // 0
		Value:   "3.1415926535",
		Mapping: os.Getenv,
		Result:  "3.1415926535",
	},
	{ // 1
		Value:   "${TEST_VALUE}",
		Mapping: func(string) string { return "3.1415926535" },
		Result:  "3.1415926535",
	},
	{ // 2
		Value:   "       ${TEST_VALUE}  ",
		Mapping: func(string) string { return "3.1415926535" },
		Result:  "3.1415926535",
	},
	{ // 3
		Value: "${TEST_VALUE}",
		Mapping: func(k string) string {
			if k == "TEST_VALUE" {
				return "3.1415926535"
			}
			return ""
		},
		Result: "3.1415926535",
	},
	{ // 4
		Value:   "${ TEST_VALUE}",
		Mapping: func(string) string { return "3.1415926535" },
		Result:  "3.1415926535",
	},
	{ // 5
		Value:   "$TEST_VALUE",
		Mapping: func(string) string { return "3.1415926535" },
		Result:  "$TEST_VALUE",
	},
	{ // 5
		Value:   "$TEST_VALUE}",
		Mapping: func(string) string { return "3.1415926535" },
		Result:  "$TEST_VALUE}",
	},
}
