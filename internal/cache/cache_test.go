// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package cache

import (
	"testing"

	key "github.com/minio/keys"
)

func TestCacheSet(t *testing.T) {
	var secret key.Secret
	secret[0] = 0xff

	var c Cache
	c.Set("0", secret)
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}
	c.Set("1", secret)

	secret[0] = 0x11
	c.Set("0", secret)
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}
}

func TestCacheAdd(t *testing.T) {
	var secret key.Secret
	secret[0] = 0xff

	var c Cache
	if s, ok := c.Add("0", secret); !ok || s != secret {
		t.Fatalf("Expected to be able to add an entry: got: %x - want: %x", s, secret)
	}
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}

	secret[0] = 0x11
	if s, ok := c.Add("0", secret); ok || s == secret {
		t.Fatal("Cache entry should already exist")
	}
}

func TestCacheGet(t *testing.T) {
	var secret key.Secret
	secret[0] = 0xff

	var c Cache
	c.Set("0", secret)
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}
	if s, ok := c.Get("1"); ok || s == secret {
		t.Fatal("Cache entry should not exist")
	}
}

func TestCacheDelete(t *testing.T) {
	var secret key.Secret
	secret[0] = 0xff

	var c Cache
	c.Set("0", secret)
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}

	c.Delete("0")
	c.Delete("1")

	if s, ok := c.Get("0"); ok || s == secret {
		t.Fatal("Cache entry should not exist")
	}
}

func TestCacheClear(t *testing.T) {
	var secret key.Secret
	secret[0] = 0xff

	var c Cache
	c.Set("0", secret)
	c.Set("1", secret)
	if s, ok := c.Get("0"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}
	if s, ok := c.Get("1"); !ok || s != secret {
		t.Fatalf("Expected to find cache entry: got: %x - want: %x", s, secret)
	}

	c.Clear()

	if s, ok := c.Get("0"); ok || s == secret {
		t.Fatal("Cache entry should not exist")
	}
	if s, ok := c.Get("1"); ok || s == secret {
		t.Fatal("Cache entry should not exist")
	}
}
