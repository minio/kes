// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"os"

	"github.com/minio/kes/internal/yml"
	"gopkg.in/yaml.v3"
)

// InitConfig is a structure containing all
// possible KES initialization configuration
// fields.
type InitConfig struct {
	Address yml.String `yaml:"address"`

	System struct {
		Admin struct {
			Identity yml.Identity `yaml:"identity"`
		} `yaml:"admin"`
	} `yaml:"system"`

	TLS struct {
		PrivateKey  yml.String `yaml:"key"`
		Certificate yml.String `yaml:"cert"`
		Password    yml.String `yaml:"password"`

		Client struct {
			VerifyCerts yml.Bool `yaml:"verify_cert"`
		} `yaml:"client"`
	} `yaml:"tls"`

	Unseal struct {
		Environment struct {
			Name string `yaml:"name"`
		} `yaml:"environment"`
	} `yaml:"unseal"`

	Enclave map[string]struct {
		Admin struct {
			Identity yml.Identity `yaml:"identity"`
		} `yaml:"admin"`

		Policy map[string]struct {
			Allow []string `yaml:"allow"`
			Deny  []string `yaml:"deny"`
		} `yaml:"policy"`
	} `yaml:"enclave"`
}

// ReadInitConfig reads and parses the InitConfig YAML representation
// from the given file.
func ReadInitConfig(filename string) (*InitConfig, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config InitConfig
	if err := yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
