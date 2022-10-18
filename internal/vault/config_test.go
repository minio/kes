// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"testing"
	"time"
)

func TestCloneConfig(t *testing.T) {
	for i, a := range cloneConfigTests {
		if b := a.Clone(); *a != *b {
			t.Fatalf("Test %d: cloned config does not match original", i)
		}
	}
}

var cloneConfigTests = []*Config{
	{
		Endpoint:   "https://vault.cluster.local:8200",
		Engine:     "secrets",
		APIVersion: APIv2,
		Namespace:  "ns-1",
		Prefix:     "my-prefix",
		AppRole: AppRole{
			Engine: "auth",
			ID:     "be7f3c83-9733-4d65-adaa-7eeb6e14e922",
			Secret: "ba8d68af-23c4-4199-a516-e37cebdaab48",
			Retry:  30 * time.Second,
		},
		K8S: Kubernetes{
			Engine: "auth",
			Role:   "kes",
			JWT:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		},
		StatusPingAfter: 15 * time.Second,
		PrivateKey:      "/tmp/kes/vault.key",
		Certificate:     "/tmp/kes/vault.crt",
		CAPath:          "/tmp/kes/vautl.ca",
	},
}
