// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package openstack

import (
	"context"

	"github.com/minio/kes/kv"
)

type iterator struct {
	ch     <-chan string
	ctx    context.Context
	cancel context.CancelCauseFunc
}

var _ kv.Iter[string] = (*iterator)(nil)

// Next moves the iterator to the next key, if any.
// This key is available until Next is called again.
//
// It returns true if and only if there is a new key
// available. If there are no more keys or an error
// has been encountered, Next returns false.
func (i *iterator) Next() (string, bool) {
	select {
	case v, ok := <-i.ch:
		return v, ok
	case <-i.ctx.Done():
		return "", false
	}
}

// Err returns the first error, if any, encountered
// while iterating over the set of keys.
func (i *iterator) Close() error {
	// i.cancel(context.Canceled)
	return context.Cause(i.ctx)
}