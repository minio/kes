// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package headers

import (
	"net/http"
	"testing"
)

func TestAccepts(t *testing.T) {
	for i, test := range acceptsTests {
		if accept := Accepts(test.Headers, test.ContentType); accept != test.Accept {
			t.Errorf("Test %d: got '%v' - want '%v' for content type '%s'", i, accept, test.Accept, test.ContentType)
		}
	}
}

var acceptsTests = []struct {
	Headers     http.Header
	ContentType string
	Accept      bool
}{
	{http.Header{}, "", false},                                                                   // 0
	{http.Header{Accept: []string{}}, "", false},                                                 // 1
	{http.Header{Accept: []string{ContentTypeJSON}}, ContentTypeHTML, false},                     // 2
	{http.Header{Accept: []string{ContentTypeHTML, ContentTypeBinary}}, ContentTypeBinary, true}, // 3

	{http.Header{Accept: []string{"*/*"}}, ContentTypeBinary, true}, // 4
	{http.Header{Accept: []string{"*/*"}}, ContentTypeHTML, true},   // 5
	{http.Header{Accept: []string{"*/*"}}, "", true},                // 6
	{http.Header{Accept: []string{"*"}}, ContentTypeHTML, false},    // 7

	{http.Header{Accept: []string{"text/*"}}, ContentTypeHTML, true},          // 8
	{http.Header{Accept: []string{"text/*"}}, ContentTypeJSON, false},         // 9
	{http.Header{Accept: []string{"text*"}}, ContentTypeHTML, false},          // 10
	{http.Header{Accept: []string{"application/*"}}, ContentTypeBinary, true}, // 11
	{http.Header{Accept: []string{"application/*"}}, ContentTypeJSON, true},   // 12
}
