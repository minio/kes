// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import "github.com/minio/kes"

// serverConfigV0135 represents a KES server configuration up to
// v0.13.5. It provides backward-compatible unmarshaling of exiting
// configuration files.
//
// It will be removed at some time in the future.
type serverConfigV0135 struct {
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

	Policies map[string]struct {
		Paths      []string       `yaml:"paths"`
		Identities []kes.Identity `yaml:"identities"`
	} `yaml:"policy"`

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

	Keys kmsServerConfig `yaml:"keys"`
}

func (c *serverConfigV0135) Migrate() serverConfig {
	config := serverConfig{
		Addr:     c.Addr,
		Cache:    c.Cache,
		Log:      c.Log,
		KeyStore: c.Keys,
	}
	config.Admin.Identity = c.Root

	config.TLS.KeyPath = c.TLS.KeyPath
	config.TLS.CertPath = c.TLS.CertPath
	config.TLS.Proxy = c.TLS.Proxy

	config.Policies = make(map[string]policyConfig, len(c.Policies))
	for name, policy := range c.Policies {
		config.Policies[name] = policyConfig{
			Allow:      policy.Paths,
			Identities: policy.Identities,
		}
	}
	return config
}
