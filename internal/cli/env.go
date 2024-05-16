// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"os"
)

// Environment variable used by the KES CLI.
const (
	// EnvServer is the server endpoint the client uses. If not set,
	// clients will use '127.0.0.1:7373'.
	EnvServer = "MINIO_KES_SERVER"

	// EnvAPIKey is used by the client to authenticate to the server.
	EnvAPIKey = "MINIO_KES_API_KEY"

	EnvPrivateKey = "MINIO_KES_KEY_FILE"

	EnvCertificate = "MINIO_KES_CERT_FILE"
)

// Env retrieves the value of the environment variable named by the key.
// It returns the value, which will be empty if the variable is not present.
func Env(key string) string {
	switch key {
	default:
		return os.Getenv(key)
	case EnvServer:
		const (
			EnvServerLegacy = "KES_SERVER"
			EnvServerMinIO  = "MINIO_KMS_KES_ENDPOINT"
			DefaultServer   = "127.0.0.1:7373"
		)
		if s, ok := os.LookupEnv(EnvServer); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvServerLegacy); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvServerMinIO); ok {
			return s
		}
		return DefaultServer

	case EnvAPIKey:
		const (
			EnvAPIKeyLegacy = "KES_API_KEY"
			EnvAPIKeyMinIO  = "MINIO_KMS_KES_API_KEY"
		)
		if s, ok := os.LookupEnv(EnvAPIKey); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvAPIKeyLegacy); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvAPIKeyMinIO); ok {
			return s
		}
		return ""

	case EnvPrivateKey:
		const (
			EnvPrivateKeyLegacy = "KES_CLIENT_KEY"
			EnvPrivateKeyMinIO  = "MINIO_KES_CLIENT_KEY"
		)
		if s, ok := os.LookupEnv(EnvPrivateKey); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvPrivateKeyLegacy); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvPrivateKeyMinIO); ok {
			return s
		}
		return ""

	case EnvCertificate:
		const (
			EnvCertificateLegacy = "KES_CLIENT_CERT"
			EnvCertificateMinIO  = "MINIO_KES_CLIENT_CERT"
		)
		if s, ok := os.LookupEnv(EnvCertificate); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvCertificateLegacy); ok {
			return s
		}
		if s, ok := os.LookupEnv(EnvCertificateMinIO); ok {
			return s
		}
		return ""
	}
}
