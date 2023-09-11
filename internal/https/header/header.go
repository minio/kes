// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package header defines common HTTP headers and header values.
package header

// Commonly used HTTP headers.
const (
	Accept           = "Accept"            // RFC 2616
	Authorization    = "Authorization"     // RFC 2616
	ContentType      = "Content-Type"      // RFC 2616
	ContentLength    = "Content-Length"    // RFC 2616
	ETag             = "ETag"              // RFC 2616
	TransferEncoding = "Transfer-Encoding" // RFC 2616
)

// Commonly used HTTP headers for forwarding originating
// IP addresses of clients connecting through an reverse
// proxy or load balancer.
const (
	Forwarded     = "Forwarded"       // RFC 7239
	XForwardedFor = "X-Forwarded-For" // Non-standard
	XFrameOptions = "X-Frame-Options" // Non-standard
)

// Commonly used HTTP content type values.
const (
	ContentTypeBinary    = "application/octet-stream"
	ContentTypeJSON      = "application/json"
	ContentTypeJSONLines = "application/x-ndjson"
)
