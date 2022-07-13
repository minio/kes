// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import "time"

// State is a KES server status snapshot.
type State struct {
	Version    string        `json:"version"`        // KES server version
	OS         string        `json:"os"`             // OS running the KES server
	Arch       string        `json:"arch"`           // CPU architecture the KES server is running on
	UpTime     time.Duration `json:"uptime"`         // Time the KES server has been up and running
	CPUs       int           `json:"num_cpu"`        // Number of available logical CPU cores
	UsableCPUs int           `json:"num_cpu_used"`   // Number of usbale logical CPU cores
	HeapAlloc  uint64        `json:"num_heap_used"`  // Number of bytes currently allocated on the heap
	StackAlloc uint64        `json:"num_stack_used"` // Number of bytes currently allocated on the stack
}

// API describes a KES server API.
type API struct {
	Method  string        // The HTTP method
	Path    string        // The API path without its arguments. For example: "/v1/status"
	MaxBody int64         // The max. size of request bodies accepted
	Timeout time.Duration // Amount of time after which request will time out
}
