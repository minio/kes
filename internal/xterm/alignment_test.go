// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package xterm

import "testing"

var alignmentFormatTests = []struct {
	Alignment Alignment
	Text      string
	Length    int
	Formatted string
}{
	{Alignment: AlignLeft, Text: "", Length: 0, Formatted: ""},
	{Alignment: AlignLeft, Text: "123456", Length: 0, Formatted: ""},
	{Alignment: AlignLeft, Text: "123456", Length: 4, Formatted: "123…"},
	{Alignment: AlignLeft, Text: "123456 ", Length: 4, Formatted: "12… "},
	{Alignment: AlignLeft, Text: "123456", Length: 8, Formatted: "123456  "},

	{Alignment: AlignCenter, Text: "", Length: 0, Formatted: ""},
	{Alignment: AlignCenter, Text: "123456", Length: 0, Formatted: ""},
	{Alignment: AlignCenter, Text: "123456", Length: 4, Formatted: "123…"},
	{Alignment: AlignCenter, Text: "123456 ", Length: 4, Formatted: "12… "},
	{Alignment: AlignCenter, Text: "123456", Length: 8, Formatted: " 123456 "},

	{Alignment: AlignRight, Text: "", Length: 0, Formatted: ""},
	{Alignment: AlignRight, Text: "123456", Length: 0, Formatted: ""},
	{Alignment: AlignRight, Text: "123456", Length: 4, Formatted: "123…"},
	{Alignment: AlignRight, Text: "123456 ", Length: 4, Formatted: "12… "},
	{Alignment: AlignRight, Text: "123456", Length: 8, Formatted: "  123456"},
}

func TestAlignmentFormat(t *testing.T) {
	for i, test := range alignmentFormatTests {
		formatted := test.Alignment.Format(test.Text, test.Length)
		if formatted != test.Formatted {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, formatted, test.Formatted)
		}
	}
}
