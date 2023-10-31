// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keystore

import (
	"slices"
	"testing"
)

func TestList(t *testing.T) {
	for i, test := range listTests {
		list, continueAt, err := List(test.Names, test.Prefix, test.N)
		if err != nil {
			t.Fatalf("Test %d: failed to list: %v", i, err)
		}

		if !slices.Equal(list, test.List) {
			t.Fatalf("Test %d: listing does not match: got '%v' - want '%v'", i, list, test.List)
		}
		if continueAt != test.ContinueAt {
			t.Fatalf("Test %d: continue at does not match: got '%s' - want '%s'", i, continueAt, test.ContinueAt)
		}
	}
}

var listTests = []struct {
	Names  []string
	Prefix string
	N      int

	List       []string
	ContinueAt string
}{
	{
		Names: []string{},
		List:  []string{},
	},
	{
		Names: []string{"my-key", "my-key2", "0-key", "1-key"},
		List:  []string{"0-key", "1-key", "my-key", "my-key2"},
	},
	{
		Names:  []string{"my-key", "my-key2", "0-key", "1-key"},
		Prefix: "my",
		List:   []string{"my-key", "my-key2"},
	},
	{
		Names:      []string{"my-key", "my-key2", "0-key", "1-key"},
		Prefix:     "my",
		N:          1,
		List:       []string{"my-key"},
		ContinueAt: "my-key2",
	},
}
