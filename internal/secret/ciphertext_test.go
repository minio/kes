// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"bytes"
	"encoding/json"
	"testing"
)

var marshalCiphertextTests = []struct {
	LocalKey Secret
	KMSKey   string
	Bytes    []byte

	Output string
}{
	{ // 0
		LocalKey: Secret{},
		KMSKey:   "",
		Bytes:    nil,
		Output:   `{"local_key":{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"kms_key":"","ciphertext":null}`,
	},
	{ // 1
		LocalKey: mustDecodeSecret("e01218424a659aeb575a4320dfc7a7ada78f9ec6106ae210921cc1843ef1b3e5"),
		KMSKey:   "5f91e7d9-a376-47cd-ad6f-3485abf9122c",
		Bytes:    mustDecodeHex("0102020078056328069c2aa385a68a7d5010dd7e46f9a3175602d8446a91c53628164e7cf301c06112f393a2449acca50f3b1f5f2774000001233082011f06092a864886f70d010706a08201103082010c0201003082010506092a864886f70d010701301e060960864801650304012e3011040c29e53e22e65a8b36c9ab37aa0201108081d71da1a4c2d2f99738df327c81915b3e2c3983b5ec8d6985a11f06e50d89ac139b3cfd3556c78d9d5033d232826d9608ee038b1c52a947b7f08f0161268c0a3ddd4f3ecb9549e7617dd019d76c0666f33807a9ec6e5f276a22ec3f77a7e48aa17c81771e3605c9c595c1f3538981dec5808f4dde22a60374abef2b07dd19422528e5743da9e6bc92a61140f6d2efdbae16478f992fae600e12e087fb3482f90d3ad1ccdba90839d08affa536aabf987b5f621bc61280dac809a94fcae8413b6437deb62bb84373f78a4d95bb6ddf7e4d8b270735c89372f8"),
		Output:   `{"local_key":{"bytes":"4BIYQkplmutXWkMg38enraePnsYQauIQkhzBhD7xs+U="},"kms_key":"5f91e7d9-a376-47cd-ad6f-3485abf9122c","ciphertext":"AQICAHgFYygGnCqjhaaKfVAQ3X5G+aMXVgLYRGqRxTYoFk588wHAYRLzk6JEmsylDzsfXyd0AAABIzCCAR8GCSqGSIb3DQEHBqCCARAwggEMAgEAMIIBBQYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwp5T4i5lqLNsmrN6oCARCAgdcdoaTC0vmXON8yfIGRWz4sOYO17I1phaEfBuUNiawTmzz9NVbHjZ1QM9Iygm2WCO4DixxSqUe38I8BYSaMCj3dTz7LlUnnYX3QGddsBmbzOAep7G5fJ2oi7D93p+SKoXyBdx42BcnFlcHzU4mB3sWAj03eIqYDdKvvKwfdGUIlKOV0PanmvJKmEUD20u/brhZHj5kvrmAOEuCH+zSC+Q060czbqQg50Ir/pTaqv5h7X2IbxhKA2sgJqU/K6EE7ZDfetiu4Q3P3ik2Vu23ffk2LJwc1yJNy+A=="}`,
	},
}

func TestMarshalCiphertext(t *testing.T) {
	type Ciphertext struct {
		LocalKey Secret `json:"local_key"`
		Key      string `json:"kms_key"`
		Bytes    []byte `json:"ciphertext"`
	}
	for i, test := range marshalCiphertextTests {
		output, err := json.Marshal(Ciphertext{
			LocalKey: test.LocalKey,
			Key:      test.KMSKey,
			Bytes:    test.Bytes,
		})
		if err != nil {
			t.Fatalf("Test %d: Failed to marshal ciphertext: %v", i, err)
		}
		if string(output) != test.Output {
			t.Fatalf("Test %d: marshal output mismatch: \ngot  '%s'\nwant '%s'", i, string(output), test.Output)
		}
	}
}

var unmarshalCiphertextTests = []struct {
	Input string

	LocalKey Secret
	KMSKey   string
	Bytes    []byte
}{
	{ // 0
		Input: `{"local_key":{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"kms_key":"","ciphertext":null}`,

		LocalKey: Secret{},
		KMSKey:   "",
		Bytes:    nil,
	},
	{ // 1
		Input: `{"local_key":{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"kms_key":"5f91e7d9-a376-47cd-ad6f-3485abf9122c","ciphertext":null}`,

		LocalKey: Secret{},
		KMSKey:   "5f91e7d9-a376-47cd-ad6f-3485abf9122c",
		Bytes:    nil,
	},
	{ // 2
		Input: `{"local_key":{"bytes":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"kms_key":"","ciphertext":"u41kHS7VEy/3vJz3anJmZ9Jt2ajx4HBkcwHxmo6KiUSOzjsP3h9+0bymOosQiXvk"}`,

		LocalKey: Secret{},
		KMSKey:   "",
		Bytes:    mustDecodeHex("bb8d641d2ed5132ff7bc9cf76a726667d26dd9a8f1e070647301f19a8e8a89448ece3b0fde1f7ed1bca63a8b10897be4"),
	},
	{ // 3
		Input: `{"local_key":{"bytes":"4BIYQkplmutXWkMg38enraePnsYQauIQkhzBhD7xs+U="},"kms_key":"5f91e7d9-a376-47cd-ad6f-3485abf9122c","ciphertext":"AQICAHgFYygGnCqjhaaKfVAQ3X5G+aMXVgLYRGqRxTYoFk588wHAYRLzk6JEmsylDzsfXyd0AAABIzCCAR8GCSqGSIb3DQEHBqCCARAwggEMAgEAMIIBBQYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwp5T4i5lqLNsmrN6oCARCAgdcdoaTC0vmXON8yfIGRWz4sOYO17I1phaEfBuUNiawTmzz9NVbHjZ1QM9Iygm2WCO4DixxSqUe38I8BYSaMCj3dTz7LlUnnYX3QGddsBmbzOAep7G5fJ2oi7D93p+SKoXyBdx42BcnFlcHzU4mB3sWAj03eIqYDdKvvKwfdGUIlKOV0PanmvJKmEUD20u/brhZHj5kvrmAOEuCH+zSC+Q060czbqQg50Ir/pTaqv5h7X2IbxhKA2sgJqU/K6EE7ZDfetiu4Q3P3ik2Vu23ffk2LJwc1yJNy+A=="}`,

		LocalKey: mustDecodeSecret("e01218424a659aeb575a4320dfc7a7ada78f9ec6106ae210921cc1843ef1b3e5"),
		KMSKey:   "5f91e7d9-a376-47cd-ad6f-3485abf9122c",
		Bytes:    mustDecodeHex("0102020078056328069c2aa385a68a7d5010dd7e46f9a3175602d8446a91c53628164e7cf301c06112f393a2449acca50f3b1f5f2774000001233082011f06092a864886f70d010706a08201103082010c0201003082010506092a864886f70d010701301e060960864801650304012e3011040c29e53e22e65a8b36c9ab37aa0201108081d71da1a4c2d2f99738df327c81915b3e2c3983b5ec8d6985a11f06e50d89ac139b3cfd3556c78d9d5033d232826d9608ee038b1c52a947b7f08f0161268c0a3ddd4f3ecb9549e7617dd019d76c0666f33807a9ec6e5f276a22ec3f77a7e48aa17c81771e3605c9c595c1f3538981dec5808f4dde22a60374abef2b07dd19422528e5743da9e6bc92a61140f6d2efdbae16478f992fae600e12e087fb3482f90d3ad1ccdba90839d08affa536aabf987b5f621bc61280dac809a94fcae8413b6437deb62bb84373f78a4d95bb6ddf7e4d8b270735c89372f8"),
	},
}

func TestUnmarshalCiphertext(t *testing.T) {
	type Ciphertext struct {
		LocalKey Secret `json:"local_key"`
		Key      string `json:"kms_key"`
		Bytes    []byte `json:"ciphertext"`
	}
	for i, test := range unmarshalCiphertextTests {
		var ciphertext Ciphertext
		err := json.Unmarshal([]byte(test.Input), &ciphertext)
		if err != nil {
			t.Fatalf("Test %d: Unmarshal failed: %v", i, err)
		}

		if ciphertext.LocalKey != test.LocalKey {
			t.Fatalf("Test %d: local key mismatch: got '%x' - want '%x'", i, ciphertext.LocalKey, test.LocalKey)
		}
		if ciphertext.Key != test.KMSKey {
			t.Fatalf("Test %d: KMS key mismatch: got '%s' - want '%s'", i, ciphertext.Key, test.KMSKey)
		}

		if !bytes.Equal(ciphertext.Bytes, test.Bytes) {
			t.Fatalf("Test %d: ciphertext bytes mismatch: \ngot  '%x'\nwant '%x'", i, ciphertext.Bytes, test.Bytes)
		}

		// We also test that if we can successfully unmarshal a ciphertext
		// then we should be able to successfully marshal it as well.

		output, err := json.Marshal(ciphertext)
		if err != nil {
			t.Fatalf("Test %d: Failed to marshal ciphertext: %v", i, err)
		}
		if string(output) != test.Input {
			t.Fatalf("Test %d: marshal output mismatch: \ngot  '%s'\nwant '%s'", i, string(output), test.Input)
		}
	}
}
