// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth_test

import (
	"fmt"

	"github.com/minio/kes/internal/auth"
)

func ExamplePolicy_IsSubset() {
	parent := auth.Policy{
		Allow: map[string]auth.Rule{
			"/v1/key/create/*":          {},
			"/v1/key/describe/*":        {},
			"/v1/key/generate/*":        {},
			"/v1/key/decrypt/*":         {},
			"/v1/policy/describe/minio": {},
			"/v1/policy/show/minio":     {},
		},
	}
	child := auth.Policy{
		Allow: map[string]auth.Rule{
			"/v1/key/describe/*": {},
			"/v1/key/generate/*": {},
		},
	}
	fmt.Println(child.IsSubset(&parent))
	// Output: true
}
