// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.ackage fs

package fs

import "testing"

var validNameTests = []struct {
	Name  string
	Valid bool
}{
	{Name: "", Valid: false},
	{Name: ".", Valid: false},
	{Name: "..", Valid: false},
	{Name: ".my-key", Valid: false},
	{Name: "my.key", Valid: false},
	{Name: "/my-key", Valid: false},
	{Name: "\\my-key", Valid: false},
	{Name: "my-key/", Valid: false},
	{Name: "my/key", Valid: false},
	{Name: "./my-key", Valid: false},
	{Name: "./../my-key", Valid: false},
	{Name: "my-key", Valid: true},
}

func TestValidName(t *testing.T) {
	for i, test := range validNameTests {
		if valid := validName(test.Name) == nil; valid != test.Valid {
			t.Fatalf("Test %d: got '%v' - wanted: '%v'", i, valid, test.Valid)
		}
	}
}
