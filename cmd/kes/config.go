// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"os"
	"strings"
	"time"

	"github.com/minio/kes"
	"gopkg.in/yaml.v2"
)

type serverConfig struct {
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
			Any    time.Duration `yaml:"any"`
			Unused time.Duration `yaml:"unused"`
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error string `yaml:"error"`
		Audit string `yaml:"audit"`
	} `yaml:"log"`

	Keys struct {
		Fs struct {
			Path string `yaml:"path"`
		} `yaml:"fs"`

		Vault struct {
			Endpoint   string `yaml:"endpoint"`
			EnginePath string `yaml:"engine"`
			Namespace  string `yaml:"namespace"`

			Prefix string `yaml:"prefix"`

			AppRole struct {
				EnginePath string        `yaml:"engine"`
				ID         string        `yaml:"id"`
				Secret     string        `yaml:"secret"`
				Retry      time.Duration `yaml:"retry"`
			} `yaml:"approle"`

			TLS struct {
				KeyPath  string `yaml:"key"`
				CertPath string `yaml:"cert"`
				CAPath   string `yaml:"ca"`
			} `yaml:"tls"`

			Status struct {
				Ping time.Duration `yaml:"ping"`
			} `yaml:"status"`
		} `yaml:"vault"`

		Aws struct {
			SecretsManager struct {
				Endpoint string `yaml:"endpoint"`
				Region   string `yaml:"region"`
				KmsKey   string ` yaml:"kmskey"`

				Login struct {
					AccessKey    string `yaml:"accesskey"`
					SecretKey    string `yaml:"secretkey"`
					SessionToken string `yaml:"token"`
				} `yaml:"credentials"`
			} `yaml:"secretsmanager"`
		} `yaml:"aws"`

		Gemalto struct {
			KeySecure struct {
				Endpoint string `yaml:"endpoint"`

				Login struct {
					Token  string        `yaml:"token"`
					Domain string        `yaml:"domain"`
					Retry  time.Duration `yaml:"retry"`
				} `yaml:"credentials"`

				TLS struct {
					CAPath string `yaml:"ca"`
				} `yaml:"tls"`
			} `yaml:"keysecure"`
		} `yaml:"gemalto"`
	} `yaml:"keys"`
}

func loadServerConfig(path string) (config serverConfig, err error) {
	if path == "" {
		return config, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	if err = yaml.NewDecoder(file).Decode(&config); err != nil {
		file.Close()
		return config, err
	}

	// Replace identities that refer to env. variables with the
	// corresponding env. variable values.
	// An identity refers to an env. variable if it has the form:
	//  ${<env-var-name>}
	// We then replace the identity with the env. variable value.
	// Currently only identities can be customized via env. variables.
	if refersToEnvVar(config.Root.String()) {
		config.Root = kes.Identity(os.ExpandEnv(config.Root.String()))
	}
	for i, identity := range config.TLS.Proxy.Identities { // The TLS proxy identities section
		if refersToEnvVar(identity.String()) {
			config.TLS.Proxy.Identities[i] = kes.Identity(os.ExpandEnv(identity.String()))
		}
	}
	for _, policy := range config.Policies { // The policy section
		for i, identity := range policy.Identities {
			if refersToEnvVar(identity.String()) {
				policy.Identities[i] = kes.Identity(os.ExpandEnv(identity.String()))
			}
		}
	}
	return config, file.Close()
}

// SetDefaults set default values for fields that may be empty b/c not specified by user.
func (config *serverConfig) SetDefaults() {
	if config.Log.Audit == "" {
		config.Log.Audit = "off" // If not set, default is off.
	}
	if config.Log.Error == "" {
		config.Log.Error = "on" // If not set, default is on.
	}
	if config.Keys.Vault.EnginePath == "" {
		config.Keys.Vault.EnginePath = "kv" // If not set, use the Vault default engine path.
	}
	if config.Keys.Vault.AppRole.EnginePath == "" {
		config.Keys.Vault.AppRole.EnginePath = "approle" // If not set, use the Vault default auth path.
	}
}

// refersToEnvVar returns true if s has the following form:
//  ${<env-var-name}
//
// In this case s should be replaced by the referenced
// env. variable.
//
// refersToEnvVar ignores any leading or trailing whitespaces.
func refersToEnvVar(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}")
}
