// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

import "testing"

var readServerConfigTests = []struct {
	File string
}{
	{File: "testdata/config_v0.13.0.yml"}, // 0
	{File: "testdata/config_v0.14.0.yml"}, // 1
	{File: "testdata/config_v0.17.0.yml"}, // 2
}

func TestReadServerConfig(t *testing.T) {
	for i, test := range readServerConfigTests {
		_, err := ReadServerConfig(test.File)
		if err != nil {
			t.Fatalf("Test %d: failed to read server config %q: %v", i, test.File, err)
		}
	}
}
