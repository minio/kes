// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"time"

	key "github.com/minio/keys"
	"github.com/pelletier/go-toml"
)

type serverConfig struct {
	Addr string       `toml:"address"`
	Root key.Identity `toml:"root"`

	TLS struct {
		KeyPath  string `toml:"key"`
		CertPath string `toml:"cert"`
	} `toml:"tls"`

	Policies map[string]struct {
		Paths      []string       `toml:"paths"`
		Identities []key.Identity `toml:"identities"`
	} `toml:"policy"`

	Cache struct {
		Expiry struct {
			All    time.Duration `toml:"all"`
			Unused time.Duration `toml:"unused"`
		} `toml:"expiry"`
	} `toml:"cache"`

	Fs struct {
		Dir string `toml:"path"`
	} `toml:"fs"`

	Vault struct {
		Addr string `toml:"address"`
		Name string `toml:"name"`

		AppRole struct {
			ID     string        `toml:"id"`
			Secret string        `toml:"secret"`
			Retry  time.Duration `toml:"retry"`
		} `toml:"approle"`

		Status struct {
			Ping time.Duration `toml:"ping"`
		} `toml:"status"`
	} `toml:"vault"`
}

func loadServerConfig(path string) (config serverConfig, err error) {
	if path == "" {
		return config, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	defer file.Close()

	err = toml.NewDecoder(file).Decode(&config)
	return config, err
}
