// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func mlockall() error { return unix.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE) }
