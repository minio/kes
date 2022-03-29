// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import "time"

// Metric is a KES server metric snapshot.
type Metric struct {
	RequestOK     uint64 `json:"kes_http_request_success"` // Requests that succeeded
	RequestErr    uint64 `json:"kes_http_request_error"`   // Requests that failed with a well-defined error
	RequestFail   uint64 `json:"kes_http_request_failure"` // Requests that failed unexpectedly due to an internal error
	RequestActive uint64 `json:"kes_http_request_active"`  // Requests that are currently active and haven't completed yet

	AuditEvents uint64 `json:"kes_log_audit_events"` // Number of generated audit events
	ErrorEvents uint64 `json:"kes_log_error_events"` // Number of generated error events

	// Histogram of the KES server response latency.
	// It shows how fast the server can handle requests.
	//
	// The KES server response latency is the time
	// it takes to reply with a response once a request
	// has been received.
	//
	// The histogram consists of n time buckets. Each
	// time bucket contains the number of responses
	// that took the time T or less. For example:
	//
	//   10ms │ 50ms │ 100ms │ 250ms │ 500ms │ ...
	//   ─────┼──────┼───────┼───────┼───────┼────
	//    100 │  115 │  121  │  126  │  130  │
	//
	//   Here, there were 100 responses that took
	//   10ms or less to generate. There were also
	//   115 responses that took 50ms or less.
	//
	//   So, there were 15 responses in the window
	//   >10ms and <=50ms.
	//
	LatencyHistogram map[time.Duration]uint64 `json:"kes_http_response_time"`

	UpTime time.Duration `json:"kes_system_up_time"` // The time the KES server has been up and running

	// The number of logical CPU cores available on the system.
	//
	// The number of available CPU cores may be larger than
	// the number of cores usable by the server.
	//
	// If CPUs == UsableCPUs then the server can use the entire
	// computing power available on the system.
	CPUs int `json:"kes_system_num_cpu"`

	// The number of logical CPU cores usable by the server.
	//
	// The number of usable CPU cores may be smaller than
	// the number of available CPUs on the system. For
	// instance, a set of CPU cores may be reserved for
	// other tasks.
	UsableCPUs int `json:"kes_system_num_cpu_used"`

	// The number of concurrent co-routines/threads that currently exists.
	//
	// It may not correspond to the number of OS threads.
	Threads int `json:"kes_system_num_threads"`

	// HeapAlloc is the number of bytes currently allocated on the heap memory.
	//
	// It increases as the server allocates objects living on the heap and
	// decreases as allocated objects get freed.
	HeapAlloc uint64 `json:"kes_system_mem_heap_used"`

	// HeapObjects is the number of currently allocated objects on th heap memory.
	//
	// Similar to HeapAlloc, it increases as objects are allocated and decreases
	// as they get freed.
	HeapObjects uint64 `json:"kes_system_mem_heap_objects"`

	// StackAlloc is the number of bytes currently used on the OS stack memory.
	//
	// It increases as the server starts more co-routines / threads, invokes
	// functions, etc. and decreases as spawned co-routines / threads terminate.
	StackAlloc uint64 `json:"kes_system_mem_stack_used"`
}

// RequestN returns the total number of received requests.
func (m *Metric) RequestN() uint64 { return m.RequestOK + m.RequestErr + m.RequestFail }
