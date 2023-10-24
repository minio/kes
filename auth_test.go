// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	t.Parallel()
	for i, test := range validNameTests {
		if valid := validName(test.Name); valid != !test.ShouldFail {
			t.Errorf("Test %d: got 'valid=%v' - want 'fail=%v' for name '%s'", i, valid, test.ShouldFail, test.Name)
		}
	}
}

func TestValidPattern(t *testing.T) {
	t.Parallel()
	for i, test := range validPatternTests {
		if valid := validPattern(test.Pattern); valid != !test.ShouldFail {
			t.Errorf("Test %d: got 'valid=%v' - want 'fail=%v' for pattern '%s'", i, valid, test.ShouldFail, test.Pattern)
		}
	}
}

func BenchmarkValidName(b *testing.B) {
	const (
		EmptyName   = ""
		ValidName   = "my-minio-key"
		InvalidName = "my-minio-key*"
	)

	b.Run("empty", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validName(EmptyName)
		}
	})
	b.Run("valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validName(ValidName)
		}
	})
	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validName(InvalidName)
		}
	})
}

func BenchmarkValidPattern(b *testing.B) {
	const (
		MatchAll       = "*"
		ValidPattern   = "my-minio-key*"
		InvalidPattern = "my-minio-key/"
	)

	b.Run("matchall", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validPattern(MatchAll)
		}
	})
	b.Run("valid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validPattern(ValidPattern)
		}
	})
	b.Run("invalid", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			validPattern(InvalidPattern)
		}
	})
}

var (
	validNameTests = []struct {
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

	validPatternTests = []struct {
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
		{Pattern: ""},          // 10

		{Pattern: "*-*", ShouldFail: true},                   // 11
		{Pattern: "my.key", ShouldFail: true},                // 12
		{Pattern: "key/", ShouldFail: true},                  // 13
		{Pattern: "☰", ShouldFail: true},                     // 14
		{Pattern: "hel<lo", ShouldFail: true},                // 15
		{Pattern: "Εmacs", ShouldFail: true},                 // 16 - greek Ε
		{Pattern: strings.Repeat("a", 81), ShouldFail: true}, // 17
	}
)
