// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import "testing"

var endpointTests = []struct {
	Endpoint string
	Elements []string
	URL      string
}{
	{Endpoint: "https://127.0.0.1:7373", Elements: nil, URL: "https://127.0.0.1:7373"},
	{Endpoint: "https://127.0.0.1:7373/", Elements: nil, URL: "https://127.0.0.1:7373"},
	{Endpoint: " https://127.0.0.1:7373/ ", Elements: nil, URL: "https://127.0.0.1:7373"},

	{
		Endpoint: "https://play.min.io:7373",
		Elements: []string{"/version"},
		URL:      "https://play.min.io:7373/version",
	},
	{
		Endpoint: "https://play.min.io:7373",
		Elements: []string{"version"},
		URL:      "https://play.min.io:7373/version",
	},
	{
		Endpoint: "https://127.0.0.1:7373",
		Elements: []string{"/key/create/my-key"},
		URL:      "https://127.0.0.1:7373/key/create/my-key",
	},
	{
		Endpoint: "https://127.0.0.1:7373",
		Elements: []string{"/key", "/create", "my-key"},
		URL:      "https://127.0.0.1:7373/key/create/my-key",
	},
}

func TestEndpoint(t *testing.T) {
	for i, test := range endpointTests {
		if url := endpoint(test.Endpoint, test.Elements...); url != test.URL {
			t.Fatalf("Test %d: endpoint url mismatch: got '%s' - want '%s'", i, url, test.URL)
		}
	}
}
