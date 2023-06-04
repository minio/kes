// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import "testing"

func TestPolicyIsSubset(t *testing.T) {
	for i, test := range policyIsSubsetTests {
		subset := test.A.IsSubset(test.B)
		if subset && !test.IsSubset {
			t.Fatalf("Test %d: policy 'A' is a subset of policy 'B' but it shouldn't be", i)
		}
		if !subset && test.IsSubset {
			t.Fatalf("Test %d: policy 'A' is not a subset of policy 'B' but it should be", i)
		}

		if subset {
			equal := test.B.IsSubset(test.A)
			if equal && !test.IsEqual {
				t.Fatalf("Test %d: policy 'A' and 'B' are equal but shouldn't be", i)
			}
			if !equal && test.IsEqual {
				t.Fatalf("Test %d: policy 'A' and 'B' are not equal but should be", i)
			}
		}
	}
}

var policyIsSubsetTests = []struct {
	A, B     *Policy
	IsSubset bool
	IsEqual  bool
}{
	{ // 0
		A: &Policy{}, B: &Policy{}, IsSubset: true, IsEqual: true,
	},

	{ // 1
		A:        &Policy{Allow: map[string]Rule{"/v1/key/create/*": {}}},
		B:        &Policy{Allow: map[string]Rule{"/v1/key/create/*": {}}},
		IsSubset: true, IsEqual: true,
	},

	{ // 2
		A: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
			Deny:  map[string]Rule{"/v1/policy/create/*": {}},
		},
		B: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
			Deny:  map[string]Rule{"/v1/policy/create/*": {}},
		},
		IsSubset: true, IsEqual: true,
	},

	{ // 3
		A:        &Policy{},
		B:        &Policy{Allow: map[string]Rule{"/v1/status": {}}},
		IsSubset: true,
	},

	{ // 4
		A:        &Policy{Deny: map[string]Rule{"/v1/status": {}}},
		B:        &Policy{},
		IsSubset: true,
		IsEqual:  true,
	},

	{ // 5
		A: &Policy{
			Allow: map[string]Rule{
				"/v1/key/create/my-key": {},
				"/v1/key/create/foo*":   {},
			},
		},
		B: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
		},
		IsSubset: true,
	},

	{ // 6
		A: &Policy{
			Allow: map[string]Rule{
				"/v1/key/create/*":   {},
				"/v1/key/describe/*": {},
				"/v1/key/generate/*": {},
				"/v1/key/decrypt/*":  {},
				"/v1/key/encrypt/*":  {},
			},
			Deny: map[string]Rule{
				"/v1/key/create/internal*":   {},
				"/v1/key/describe/internal*": {},
				"/v1/key/generate/internal*": {},
				"/v1/key/decrypt/internal*":  {},
				"/v1/key/encrypt/internal*":  {},
			},
		},
		B: &Policy{
			Allow: map[string]Rule{
				"/v1/key/create/*":   {},
				"/v1/key/describe/*": {},
				"/v1/key/generate/*": {},
				"/v1/key/decrypt/*":  {},
				"/v1/key/encrypt/*":  {},
			},
			Deny: map[string]Rule{
				"/v1/key/create/internal/*":   {},
				"/v1/key/describe/internal/*": {},
				"/v1/key/generate/internal/*": {},
				"/v1/key/decrypt/internal/*":  {},
				"/v1/key/encrypt/internal/*":  {},
			},
		},
		IsSubset: true,
	},

	{ // 7
		A: &Policy{
			Allow: map[string]Rule{
				"/v1/policy/describe/minio": {},
				"/v1/policy/show/minio":     {},
				"/v1/policy/list/minio":     {},
				"/v1/identity/delete/*":     {},
			},
			Deny: map[string]Rule{
				"/v1/identity/delete/88*": {},
			},
		},
		B: &Policy{
			Allow: map[string]Rule{
				"/v1/identity/create/*":     {},
				"/v1/identity/describe/*":   {},
				"/v1/identity/list/*":       {},
				"/v1/identity/delete/*":     {},
				"/v1/policy/describe/minio": {},
				"/v1/policy/show/minio":     {},
				"/v1/policy/list/minio":     {},
			},
			Deny: map[string]Rule{
				"/v1/identity/delete/88acf8c3220a69497f2fa1fc7f52f56b9ff2996402d9379a49fbaffe2b56fdfd": {},
			},
		},
		IsSubset: true,
	},

	{ // 8
		A: &Policy{
			Allow: map[string]Rule{"/v1/status": {}},
		},
		B: &Policy{},
	},

	{ // 9
		A: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
		},
		B: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
			Deny:  map[string]Rule{"/v1/key/create/my-key": {}},
		},
	},

	{ // 10
		A: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
			Deny:  map[string]Rule{"/v1/key/create/internal*": {}},
		},
		B: &Policy{
			Allow: map[string]Rule{"/v1/key/create/*": {}},
			Deny:  map[string]Rule{"/v1/key/create/my-key": {}},
		},
	},

	{ // 11
		A: &Policy{
			Allow: map[string]Rule{
				"/v1/policy/describe/minio": {},
				"/v1/policy/show/minio":     {},
				"/v1/policy/list/minio":     {},
				"/v1/identity/delete/*":     {},
			},
			Deny: map[string]Rule{
				"/v1/identity/delete/89*": {},
			},
		},
		B: &Policy{
			Allow: map[string]Rule{
				"/v1/identity/create/*":     {},
				"/v1/identity/describe/*":   {},
				"/v1/identity/list/*":       {},
				"/v1/identity/delete/*":     {},
				"/v1/policy/describe/minio": {},
				"/v1/policy/show/minio":     {},
				"/v1/policy/list/minio":     {},
			},
			Deny: map[string]Rule{
				"/v1/identity/delete/88acf8c3220a69497f2fa1fc7f52f56b9ff2996402d9379a49fbaffe2b56fdfd": {},
			},
		},
	},
}
