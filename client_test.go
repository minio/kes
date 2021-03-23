// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"encoding/base64"
	"testing"
)

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

var dekEncodeDecodeTests = []struct {
	Key DEK
}{
	{
		Key: DEK{},
	},
	{
		Key: DEK{
			Plaintext:  nil,
			Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaXYiOiJ3NmhLUFVNZXVtejZ5UlVZL29pTFVBPT0iLCJub25jZSI6IktMSEU3UE1jRGo2N2UweHkiLCJieXRlcyI6Ik1wUkhjQWJaTzZ1Sm5lUGJGcnpKTkxZOG9pdkxwTmlUcTNLZ0hWdWNGYkR2Y0RlbEh1c1lYT29zblJWVTZoSXIifQ=="),
		},
	},
	{
		Key: DEK{
			Plaintext:  mustDecodeB64("GM2UvLXp/X8lzqq0mibFC0LayDCGlmTHQhYLj7qAy7Q="),
			Ciphertext: mustDecodeB64("eyJhZWFkIjoiQUVTLTI1Ni1HQ00tSE1BQy1TSEEtMjU2IiwiaXYiOiJ3NmhLUFVNZXVtejZ5UlVZL29pTFVBPT0iLCJub25jZSI6IktMSEU3UE1jRGo2N2UweHkiLCJieXRlcyI6Ik1wUkhjQWJaTzZ1Sm5lUGJGcnpKTkxZOG9pdkxwTmlUcTNLZ0hWdWNGYkR2Y0RlbEh1c1lYT29zblJWVTZoSXIifQ=="),
		},
	},
}

func TestEncodeDecodeDEK(t *testing.T) {
	for i, test := range dekEncodeDecodeTests {
		text, err := test.Key.MarshalText()
		if err != nil {
			t.Fatalf("Test %d: failed to marshal DEK: %v", i, err)
		}

		var key DEK
		if err = key.UnmarshalText(text); err != nil {
			t.Fatalf("Test %d: failed to unmarshal DEK: %v", i, err)
		}
		if key.Plaintext != nil {
			t.Fatalf("Test %d: unmarshaled DEK contains non-nil plaintext", i)
		}
		if !bytes.Equal(key.Ciphertext, test.Key.Ciphertext) {
			t.Fatalf("Test %d: ciphertext mismatch: got %x - want %x", i, key.Ciphertext, test.Key.Ciphertext)
		}
	}
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
