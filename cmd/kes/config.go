// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/pelletier/go-toml"
	"gopkg.in/yaml.v2"
)

type serverConfig struct {
	Addr string       `toml:"address" yaml:"address"`
	Root kes.Identity `toml:"root" yaml:"root"`

	TLS struct {
		KeyPath  string `toml:"key" yaml:"key"`
		CertPath string `toml:"cert" yaml:"cert"`
		Proxy    struct {
			Identities []kes.Identity `toml:"identities" yaml:"identities"`
			Header     struct {
				ClientCert string `toml:"cert" yaml:"cert"`
			} `toml:"header" yaml:"header"`
		} `toml:"proxy" yaml:"proxy"`
	} `toml:"tls" yaml:"tls"`

	Policies map[string]struct {
		Paths      []string       `toml:"paths" yaml:"paths"`
		Identities []kes.Identity `toml:"identities" yaml:"identities"`
	} `toml:"policy" yaml:"policy"`

	Cache struct {
		Expiry struct {
			All    time.Duration `toml:"all" yaml:"all"`
			Unused time.Duration `toml:"unused" yaml:"unused"`
		} `toml:"expiry" yaml:"expiry"`
	} `toml:"cache" yaml:"cache"`

	Log struct {
		Error struct {
			Files []string `toml:"file" yaml:"file"`
		} `toml:"error" yaml:"error"`
		Audit struct {
			Files []string `toml:"file" yaml:"file"`
		} `toml:"audit" yaml:"audit"`
	} `toml:"log" yaml:"log"`

	KMS struct {
		AWS struct {
			Addr   string `toml:"address" yaml:"address"`
			Region string `toml:"region" yaml:"region"`

			Key string `toml:"key" yaml:"key"`

			Login struct {
				AccessKey    string `toml:"access_key" yaml:"access_key"`
				SecretKey    string `toml:"secret_key" yaml:"secret_key"`
				SessionToken string `toml:"session_token" yaml:"session_token"`
			} `toml:"credentials" yaml:"credentials"`
		} `toml:"aws" yaml:"aws"`
	} `toml:"kms" yaml:"kms"`

	KeyStore struct {
		Fs struct {
			Dir string `toml:"path" yaml:"path"`
		} `toml:"fs" yaml:"fs"`

		Vault struct {
			Addr      string `toml:"address" yaml:"address"`
			Name      string `toml:"name" yaml:"name"`
			Namespace string `toml:"namespace" yaml:"namespace"`

			AppRole struct {
				ID     string        `toml:"id" yaml:"id"`
				Secret string        `toml:"secret" yaml:"secret"`
				Retry  time.Duration `toml:"retry" yaml:"retry"`
			} `toml:"approle" yaml:"approle"`

			TLS struct {
				KeyPath  string `toml:"key" yaml:"key"`
				CertPath string `toml:"cert" yaml:"cert"`
				CAPath   string `toml:"ca" yaml:"ca"`
			} `toml:"tls" yaml:"tls"`

			Status struct {
				Ping time.Duration `toml:"ping" yaml:"ping"`
			} `toml:"status" yaml:"status"`
		} `toml:"vault" yaml:"vault"`

		Aws struct {
			SecretsManager struct {
				Addr     string `toml:"address" yaml:"address"`
				Region   string `toml:"region" yaml:"region"`
				KmsKeyID string `toml:"kms_key_id" yaml:"kms_key_id"`

				Login struct {
					AccessKey    string `toml:"access_key" yaml:"access_key"`
					SecretKey    string `toml:"secret_key" yaml:"secret_key"`
					SessionToken string `toml:"session_token" yaml:"session_token"`
				} `toml:"credentials" yaml:"credentials"`
			} `toml:"secrets_manager" yaml:"secrets_manager"`
		} `toml:"aws" yaml:"aws"`
	} `toml:"keystore" yaml:"keystore"`
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

	switch {
	case strings.HasSuffix(path, ".yaml"):
		err = yaml.NewDecoder(file).Decode(&config)
		return config, err
	case strings.HasSuffix(path, ".toml"):
		err = toml.NewDecoder(file).Decode(&config)
		return config, err
	default:
		// First, try yaml. If that fails due to an invalid yaml
		// file, try toml.
		if err = yaml.NewDecoder(file).Decode(&config); err != nil {
			if _, ok := err.(*yaml.TypeError); ok {
				if err = toml.NewDecoder(file).Decode(&config); err != nil {
					return config, fmt.Errorf("%s is neither a valid yaml nor toml file", path)
				}
				return config, err
			}
		}
		return config, err
	}
}
