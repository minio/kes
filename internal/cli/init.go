// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"errors"
	"os"
	"strconv"

	"github.com/minio/kes/internal/yml"
	"gopkg.in/yaml.v3"
)

// InitConfig is a structure containing all
// possible KES initialization configuration
// fields.
type InitConfig struct {
	Version string `yaml:"version"`

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

		Proxy struct {
			Identity []yml.Identity `yaml:"identity"`
			Header   struct {
				ClientCert yml.String `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`

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
			Allow    []string       `yaml:"allow"`
			Deny     []string       `yaml:"deny"`
			Identity []yml.Identity `yaml:"identities"`
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

	var node yaml.Node
	if err := yaml.NewDecoder(f).Decode(&node); err != nil {
		return nil, err
	}

	version, err := findVersion(&node)
	if err != nil {
		return nil, err
	}
	if version != "v1" {
		return nil, errors.New("cli: invalid init config version '" + version + "'")
	}

	var config InitConfig
	if err := node.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

// findVersion finds the version field in the
// the given YAML document AST.
//
// It returns an error if the top level of the
// AST does not contain a version field.
func findVersion(root *yaml.Node) (string, error) {
	if root == nil {
		return "", errors.New("cli: invalid init config: root not found")
	}
	if root.Kind != yaml.DocumentNode {
		return "", errors.New("cli: invalid init config: not document node")
	}
	if len(root.Content) != 1 {
		return "", errors.New("cli: invalid init config: none or several root nodes")
	}

	doc := root.Content[0]
	for i, n := range doc.Content {
		if n.Value == "version" {
			if n.Kind != yaml.ScalarNode {
				return "", errors.New("cli: invalid init config version at line " + strconv.Itoa(n.Line))
			}
			if i == len(doc.Content)-1 {
				return "", errors.New("cli: invalid init config version at line " + strconv.Itoa(n.Line))
			}
			v := doc.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				return "", errors.New("cli: invalid init config version at line " + strconv.Itoa(v.Line))
			}
			return v.Value, nil
		}
	}
	return "", errors.New("cli: invalid init config: missing 'version' field")
}
