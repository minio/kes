// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import "github.com/minio/kes"

// serverConfigV0170 represents a KES server configuration between v0.14.0
// and v0.17.0. It provides backward-compatible unmarshaling of exiting
// configuration files.
//
// It will be removed at some time in the future - once serverConfigV0140
// got removed.
type serverConfigV0170 struct {
	Addr string       `yaml:"address"`
	Root kes.Identity `yaml:"root"`

	TLS struct {
		KeyPath  string `yaml:"key"`
		CertPath string `yaml:"cert"`
		Proxy    struct {
			Identities []kes.Identity `yaml:"identities"`
			Header     struct {
				ClientCert string `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`
	} `yaml:"tls"`

	Policies map[string]policyConfig `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any    duration `yaml:"any"`    // Use custom type for env. var support
			Unused duration `yaml:"unused"` // Use custom type for env. var support
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error string `yaml:"error"`
		Audit string `yaml:"audit"`
	} `yaml:"log"`

	Keys []struct {
		Name string `yaml:"name"`
	} `yaml:"keys"`

	KeyStore kmsServerConfig `yaml:"keystore"`
}

func (s *serverConfigV0170) Migrate() serverConfig {
	var config = serverConfig{
		Addr:     s.Addr,
		TLS:      s.TLS,
		Policies: s.Policies,
		Cache:    s.Cache,
		Log:      s.Log,
		Keys:     s.Keys,
		KeyStore: s.KeyStore,
	}
	config.Admin.Identity = s.Root
	return config
}
