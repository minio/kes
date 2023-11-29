// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"testing"

	"github.com/minio/kes"
	kesdk "github.com/minio/kes-go"
)

type SetupFunc func(context.Context, kes.KeyStore, string) error

const ranStringLength = 8

var createTests = []struct {
	Args       map[string][]byte
	Setup      SetupFunc
	ShouldFail bool
}{
	{ // 0
		Args: map[string][]byte{"edge-test": []byte("edge-test-value")},
	},
	{ // 1
		Args: map[string][]byte{"edge-test": []byte("edge-test-value")},
		Setup: func(ctx context.Context, s kes.KeyStore, suffix string) error {
			return s.Create(ctx, "edge-test-"+suffix, []byte("t"))
		},
		ShouldFail: true,
	},
}

func testCreate(ctx context.Context, store kes.KeyStore, t *testing.T, seed string) {
	defer clean(ctx, store, t)
	for i, test := range createTests {
		if test.Setup != nil {
			if err := test.Setup(ctx, store, fmt.Sprintf("%s-%d", seed, i)); err != nil {
				t.Fatalf("Test %d: failed to setup: %v", i, err)
			}
		}

		for key, value := range test.Args {
			secretKet := fmt.Sprintf("%s-%s-%d", key, seed, i)
			err := store.Create(ctx, secretKet, value)
			if err != nil && !test.ShouldFail {
				t.Errorf("Test %d: failed to create key '%s': %v", i, secretKet, err)
			}
			if err == nil && test.ShouldFail {
				t.Errorf("Test %d: creating key '%s' should have failed: %v", i, secretKet, err)
			}
		}
	}
}

var getTests = []struct {
	Args       map[string][]byte
	Setup      SetupFunc
	ShouldFail bool
}{
	{ // 0
		Args: map[string][]byte{"edge-test": []byte("edge-test-value")},
		Setup: func(ctx context.Context, s kes.KeyStore, suffix string) error {
			return s.Create(ctx, "edge-test-"+suffix, []byte("edge-test-value"))
		},
	},
	{ // 1
		Args:       map[string][]byte{"edge-test": []byte("edge-test-value")},
		ShouldFail: true,
	},
	{ // 1
		Args: map[string][]byte{"edge-test": []byte("edge-test-value")},
		Setup: func(ctx context.Context, s kes.KeyStore, suffix string) error {
			return s.Create(ctx, "edge-test-"+suffix, []byte("edge-test-value2"))
		},
		ShouldFail: true,
	},
}

func testGet(ctx context.Context, store kes.KeyStore, t *testing.T, seed string) {
	defer clean(ctx, store, t)
	for i, test := range getTests {
		if test.Setup != nil {
			if err := test.Setup(ctx, store, fmt.Sprintf("%s-%d", seed, i)); err != nil {
				t.Fatalf("Test %d: failed to setup: %v", i, err)
			}
		}

		for key, value := range test.Args {
			secretKet := fmt.Sprintf("%s-%s-%d", key, seed, i)
			v, err := store.Get(ctx, secretKet)
			if !test.ShouldFail {
				if err != nil {
					t.Errorf("Test %d: failed to get key '%s': %v", i, secretKet, err)
				}
				if !bytes.Equal(v, value) {
					t.Errorf("Test %d: failed to get key: got '%s' - want '%s'", i, string(v), string(value))
				}
			}
			if test.ShouldFail && err == nil && bytes.Equal(v, value) {
				t.Errorf("Test %d: getting key '%s' should have failed: %v", i, secretKet, err)
			}
		}
	}
}

func testStatus(ctx context.Context, store kes.KeyStore, t *testing.T) {
	if _, err := store.Status(ctx); err != nil {
		t.Fatalf("Failed to fetch status: %v", err)
	}
}

var osCtx, _ = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)

func testingContext(t *testing.T) (context.Context, context.CancelFunc) {
	d, ok := t.Deadline()
	if !ok {
		return osCtx, func() {}
	}
	return context.WithDeadline(osCtx, d)
}

func clean(ctx context.Context, store kes.KeyStore, t *testing.T) {
	iter := kesdk.ListIter[string]{
		NextFunc: store.List,
	}

	var names []string
	for next, err := iter.Next(ctx); err != io.EOF; next, err = iter.Next(ctx) {
		if err != nil {
			t.Errorf("Cleanup: failed to list: %v", err)
		}
		names = append(names, next)
	}
	for _, name := range names {
		if err := store.Delete(ctx, name); err != nil && !errors.Is(err, kesdk.ErrKeyNotFound) {
			t.Errorf("Cleanup: failed to delete '%s': %v", name, err)
		}
	}
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
