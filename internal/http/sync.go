// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package http

import "sync"

// Sync calls f while holding the given lock and
// releases the lock once f has been finished.
//
// Sync returns the error returned by f, if  any.
func Sync(locker sync.Locker, f func() error) error {
	locker.Lock()
	defer locker.Unlock()

	return f()
}

// VSync calls f while holding the given lock and
// releases the lock once f has been finished.
//
// VSync returns the result of f and its error
// if  any.
func VSync[V any](locker sync.Locker, f func() (V, error)) (V, error) {
	locker.Lock()
	defer locker.Unlock()

	return f()
}
