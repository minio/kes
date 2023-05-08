// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kv_test

import (
	"fmt"
	"log"

	"github.com/minio/kes/kv"
)

func ExampleIter() {
	iter := SliceIter("Hello", "World", "!")
	defer iter.Close()

	for v, ok := iter.Next(); ok; v, ok = iter.Next() {
		fmt.Println(v)
	}
	if err := iter.Close(); err != nil {
		log.Fatalln(err)
	}
	// Output:
	// Hello
	// World
	// !
}

func SliceIter[T any](v ...T) kv.Iter[T] {
	return &iter[T]{
		values: v,
	}
}

type iter[T any] struct {
	values []T
	off    int
	closed bool
}

func (i *iter[T]) Next() (v T, ok bool) {
	if i.off < len(i.values) && !i.closed {
		v, ok = i.values[i.off], true
		i.off++
	}
	return
}

func (i *iter[T]) Close() error {
	i.closed = true
	return nil
}
