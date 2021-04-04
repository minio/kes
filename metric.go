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
}

// RequestN returns the total number of received requests.
func (m *Metric) RequestN() uint64 { return m.RequestOK + m.RequestErr + m.RequestFail }
