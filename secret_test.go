// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"testing"
)

func TestSecretType_String(t *testing.T) {
	for i, test := range secretTypeStringTests {
		if s := test.Type.String(); s != test.String {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, s, test.String)
		}
	}
}

var secretTypeStringTests = []struct {
	Type   SecretType
	String string
}{
	{Type: 0, String: "generic"},             // 0
	{Type: SecretGeneric, String: "generic"}, // 1

	{Type: 1, String: "%1"}, // 2 - invalid type
}

func TestSecretType_MarshalText(t *testing.T) {
	for i, test := range secretTypeMarshalTextTests {
		text, err := test.Type.MarshalText()
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should have failed but passed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to MarshalText: %v", i, err)
		}
		if err == nil {
			if !bytes.Equal(text, test.Text) {
				t.Fatalf("Test %d: got '%s' - want '%s'", i, string(text), string(test.Text))
			}
		}
	}
}

var secretTypeMarshalTextTests = []struct {
	Type       SecretType
	Text       []byte
	ShouldFail bool
}{
	{Type: 0, Text: []byte("generic")},             // 0
	{Type: SecretGeneric, Text: []byte("generic")}, // 1

	{Type: 1, ShouldFail: true}, // 2 - invalid type
}

func TestSecretType_UnmarshalText(t *testing.T) {
	for i, test := range secretTypeUnmarshalTextTests {
		var kind SecretType
		err := kind.UnmarshalText(test.Text)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d: should have failed but passed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to UnmarshalText: %v", i, err)
		}
		if err == nil {
			if kind != test.Type {
				t.Fatalf("Test %d: got '%d' - want '%d'", i, uint(kind), uint(test.Type))
			}
		}
	}
}

var secretTypeUnmarshalTextTests = []struct {
	Text       []byte
	Type       SecretType
	ShouldFail bool
}{
	{Text: []byte("generic"), Type: SecretGeneric}, // 0

	{Text: nil, ShouldFail: true},
	{Text: []byte{}, ShouldFail: true},
	{Text: []byte(""), ShouldFail: true},
	{Text: []byte("unknown"), ShouldFail: true},
}
