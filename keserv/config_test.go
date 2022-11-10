// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"bytes"
	"testing"
	"time"

	"github.com/minio/kes"
)

func TestReadServerConfig(t *testing.T) {
	for i, test := range readServerConfigTests {
		_, err := ReadServerConfig(test.Filename)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should fail but passed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to read server config: %v", i, err)
		}
	}
}

var readServerConfigTests = []struct {
	Filename   string
	ShouldFail bool
}{
	{Filename: "./testdata/fs.yml"},
	{Filename: "./testdata/with_tls_ca.yml"},

	{Filename: "./testdata/invalid_keys.yml", ShouldFail: true},
	{Filename: "./testdata/invalid_root.yml", ShouldFail: true},
}

func TestRoundtripServerConfig(t *testing.T) {
	for i, config := range roundtripServerConfigTests {
		var buffer bytes.Buffer
		if err := EncodeServerConfig(&buffer, &config); err != nil {
			t.Fatalf("Test %d: failed to encode config: %v", i, err)
		}
		if _, err := DecodeServerConfig(&buffer); err != nil {
			t.Fatalf("Test %d: failed to encode config: %v", i, err)
		}
	}
}

var roundtripServerConfigTests = []ServerConfig{
	{
		Addr:  Env[string]{Value: "0.0.0.0:7373"},
		Admin: Env[kes.Identity]{Value: "disabled"},
	},
	{
		Addr:  Env[string]{Value: "0.0.0.0:7373"},
		Admin: Env[kes.Identity]{Value: "disabled"},
		TLS: TLSConfig{
			Password:    Env[string]{Value: "horse battery staple"},
			PrivateKey:  Env[string]{Value: "/tmp/private.key"},
			Certificate: Env[string]{Value: "/tmp/public.crt"},
			CAPath:      Env[string]{Value: "/tmp/CAs"},
			Proxies: []Env[kes.Identity]{
				{Value: "bf8d6fd2cffc6bf98f423013c13559ae2c25cfd3cd0c76f626901c95aa8c3eff"},
			},
			ForwardCertHeader: Env[string]{Value: "Client-Cert"},
		},
		Cache: CacheConfig{
			Expiry:        Env[time.Duration]{Value: 5*time.Minute + 30*time.Second},
			ExpiryUnused:  Env[time.Duration]{Value: 30 * time.Second},
			ExpiryOffline: Env[time.Duration]{Value: 1 * time.Hour},
		},
		Log: LogConfig{
			Audit: Env[string]{Value: "off"},
			Error: Env[string]{Value: "on"},
		},
		Policies: map[string]Policy{
			"my-policy": {
				Allow: []string{
					"/v1/key/create/*",
					"/v1/key/generate/*",
					"/v1/key/decrypt/*",
					"/v1/key/delete/*",
				},
				Deny: []string{
					"/v1/key/decrypt/disallowed-key",
				},
				Identities: []Env[kes.Identity]{
					{Value: "74c51d3e53094d1a6c35c667ae0d122150b867deb564dc17cc2249b9a1af3a78"},
				},
			},
		},
		Keys: []Key{
			{
				Name: Env[string]{Value: "my-key-1"},
			},
			{
				Name: Env[string]{Value: "my-key-2"},
			},
		},
		KMS: &FSConfig{
			Dir: Env[string]{Value: "/tmp/keys"},
		},
	},
}
