// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cache

import "testing"

func TestCowZeroValue(t *testing.T) {
	t.Run("Get", func(t *testing.T) {
		var cow Cow[int, string]
		if v, ok := cow.Get(0); ok {
			t.Fatalf("Empty Cow contains value: %v", v)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		var cow Cow[int, string]
		if cow.Delete(0) {
			t.Fatal("Empty Cow contains value")
		}
	})
	t.Run("DeleteAll", func(*testing.T) {
		var cow Cow[int, string]
		cow.DeleteAll() // Check whether this panics for an empty Cow
	})
	t.Run("DeleteFunc", func(*testing.T) {
		var cow Cow[int, string]
		cow.DeleteFunc(func(_ int, _ string) bool { return true }) // Check whether this panics for an empty Cow
	})
	t.Run("Set", func(t *testing.T) {
		var cow Cow[int, string]
		if !cow.Set(0, "Hello") {
			t.Fatal("Failed to insert value into empty Cow")
		}
	})
	t.Run("Add", func(t *testing.T) {
		var cow Cow[int, string]
		if !cow.Add(0, "Hello") {
			t.Fatal("Failed to add value to empty Cow")
		}
		if cow.Add(0, "World") {
			t.Fatal("Added the same key to an empty Cow twice")
		}
	})
}

func TestCowCapacity(t *testing.T) {
	const Cap = 3

	c := NewCow[int, string](Cap)
	if !c.Add(0, "Hello") {
		t.Fatalf("Failed to add '%d'", 0)
	}
	if !c.Add(1, "World") {
		t.Fatalf("Failed to add '%d'", 1)
	}
	if !c.Add(2, "!") {
		t.Fatalf("Failed to add '%d'", 2)
	}
	if c.Add(3, "") {
		t.Fatalf("Added more than '%d' keys to Cow", Cap)
	}
	if c.Set(3, "") {
		t.Fatalf("Added more than '%d' keys to Cow", Cap)
	}
	if !c.Set(2, "") {
		t.Fatalf("Failed to replace existing entry even though capacity limited has been reached")
	}

	if !c.Delete(2) {
		t.Fatalf("Failed to delete '%d'", 2)
	}
	if !c.Add(3, "") {
		t.Fatalf("Failed to add '%d'", 3)
	}
}
