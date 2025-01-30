// Copyright 2025 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package log

// Format defines a type of different log output formats,
// used by audit and error events if no custom log handler specified.
type Format string

const (
	// TextFormat creates plain text formatted log message
	TextFormat Format = "Text"

	// JSONFormat creates JSON formatted log messages
	JSONFormat Format = "JSON"
)
