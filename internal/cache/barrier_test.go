// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cache

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBarrierZeroValue(t *testing.T) {
	t.Run("Lock", func(t *testing.T) {
		var b Barrier[int]
		b.Lock(0)
		b.Unlock(0)
	})
	t.Run("Unlock", func(t *testing.T) {
		defer func() {
			const Msg = "cache: unlock of unlocked Barrier key"

			switch err := recover(); {
			case err == nil:
				t.Fatal("Unlock should have panic'ed")
			case err != Msg:
				t.Fatalf("Panic should be '%v' - got '%v'", Msg, err)
			}
		}()

		var b Barrier[int]
		b.Lock(0)
		b.Unlock(1) // Panic
	})
}

func TestBarrierLock(t *testing.T) {
	const N = 3
	var (
		b   Barrier[int]
		ctr [N]atomic.Uint32
		wg  sync.WaitGroup
	)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			runtime.Gosched() // make a potential race condition more likely

			defer wg.Done()

			b.Lock(i % N)
			defer b.Unlock(i % N)

			defer ctr[i%N].Add(^uint32(0)) // ctr = ctr - 1 | Ref: sync/atomic docs

			if ctr[i%N].Load() != 0 {
				t.Errorf("Concurrent access to counter detected: Barrier allows concurrent access to %d", i)
			}
			ctr[i%N].Add(1)
			time.Sleep(10 * time.Microsecond) // make a potential race condition more likely
		}(i)
	}
	wg.Wait()
}
