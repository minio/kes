// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

// Environment variable used by the KES CLI.
const (
	// EnvServer is the server endpoint the client uses. If not set,
	// clients will use '127.0.0.1:7373'.
	EnvServer = "MINIO_KES_SERVER"

	// EnvAPIKey is used by the client to authenticate to the server.
	EnvAPIKey = "MINIO_KES_API_KEY"
)
