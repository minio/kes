// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package xterm

import (
	"fmt"
	"strings"
)

const (
	AlignLeft Alignment = iota
	AlignCenter
	AlignRight
)

// Alignment is a text alignment.
// A text can be:
//   - aligned to left:   "foo123    "
//   - aligned to center: "  foo123  "
//   - aligned to right:  "    foo123"
//
// By default, text is aligned to the left.
type Alignment int

// Format aligns the given text and returns a
// string that is exactly length runes long.
//
// If text is exactly length runes long then Format
// returns text unmodified.
//
// If text consists of fewer then length runes then
// Format pads text to the given length with whitespaces
// depending on the alignment:
//  - AlignLeft:   whitespaces are added at the end
//  - AlignRight:  whitespaces are added at the beginning
//  - AlignCenter: whitespaces are added at the end and
//                 the beginning. If length is odd an additional
//                 whitespaces is added at the end.
//
// If text consists of more then length runes then Format
// truncates text to length runes. If text consits of at
// least 2 runes it replaces length-1 rune with '…' to
// visually indicate that the text has been truncated.
// If text ends with one or more whitespaces then Format
// replaces the length-2 rune with '…' and preserves one
// whitespace at the end.
func (a Alignment) Format(text string, length int) string {
	r := []rune(text)
	if len(r) == length {
		return text
	}
	if len(r) > length {
		if length >= 2 {
			if len(r) >= 2 && r[len(r)-1] == ' ' {
				r[length-1], r[length-2] = ' ', '…'
			} else {
				r[length-1] = '…'
			}
		}
		return string(r[:length])
	}

	switch n := length - len(r); a {
	case AlignLeft:
		return text + strings.Repeat(" ", n)
	case AlignCenter:
		p := strings.Repeat(" ", n/2)
		if n%2 == 0 {
			return p + text + p
		}
		return p + text + p + " "
	case AlignRight:
		return strings.Repeat(" ", n) + text
	default:
		panic(fmt.Sprintf("invalid alignment: %v", a))
	}
}
