// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"crypto/tls"
	"fmt"
	"log"
	"testing"

	"github.com/minio/kes"
)

func ExampleParseAPIKey() {
	key, err := kes.ParseAPIKey("kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key)
	// Output:
	// kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs
}

func ExampleGenerateCertificate() {
	key, err := kes.GenerateAPIKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := kes.GenerateCertificate(key)
	if err != nil {
		log.Fatal(err)
	}

	_ = &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}
	// Output:
}

func ExampleAPIKey_Identity() {
	key, err := kes.ParseAPIKey("kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(key.Identity())
	// Output:
	// ea9826089311fe44d7590408ede9150f7c637b6cab0a91ee6fe1aa5d9fb366f6
}

func TestParseAPIKey(t *testing.T) {
	for i, test := range parseAPIKeyTests {
		key, err := kes.ParseAPIKey(test.String)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: parsing APIKey should have failed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to parse APIKey: %v", i, err)
		}
		if err == nil {
			if s := key.String(); s != test.String {
				t.Fatalf("Test %d: got '%s' - want '%s'", i, s, test.String)
			}
		}
	}
}

func TestAPIKey_Identity(t *testing.T) {
	for i, test := range apiKeyIdentityTests {
		key, err := kes.ParseAPIKey(test.Key)
		if err != nil {
			t.Fatalf("Test %d: failed to parse APIKey: %v", i, err)
		}
		if id := key.Identity(); id != test.Identiy {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, id, test.Identiy)
		}
	}
}

var parseAPIKeyTests = []struct {
	String     string
	ShouldFail bool
}{
	{String: "kes:v1:AGaV6VXHasF0FnaB60WdCOeTZ8eTIDikL4zlN16c8NAs"},
	{String: "kes:v1:AM0F5TP43FYEShMzA42f2drFYGnBOiNx7UH4DK0nm08E"},

	{String: "v1:AM0F5TP43FYEShMzA42f2drFYGnBOiNx7UH4DK0nm08E", ShouldFail: true},
	{String: "kes:AM0F5TP43FYEShMzA42f2drFYGnBOiNx7UH4DK0nm08E", ShouldFail: true},
	{String: "kes:v1:sbDvZFqUPFFwxRS4EkuoEb2nyyInkdKSUEYHXFHeTouW", ShouldFail: true},
}

var apiKeyIdentityTests = []struct {
	Key     string
	Identiy kes.Identity
}{
	{Key: "kes:v1:ACQpoGqx3rHHjT938Hfu5hVVQJHZWSqVI2Xp1KlYxFVw", Identiy: "0426fa9a04bc2756b92fbe8a97e1a1e07b53ecf04ed33da22c33e5c9faeb8cbb"},
	{Key: "kes:v1:AMxvd2uV1l5dDSRwuKZxSjuM5BDemlr+685+JAHA1TuJ", Identiy: "ab785e3b95d80d72cc9c27cb9fde886a0bf9068a69d40e3bd08a54e68c3f2bf7"},
}
