// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// +build !linux

package main

func mlockall() error {
	// We only support locking memory pages
	// on linux at the moment.
	return nil
}
