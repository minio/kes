// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import "time"

// State is a KES server status snapshot.
type State struct {
	Version string // The KES server version

	UpTime time.Duration // The time the KES server has been up and running
}
