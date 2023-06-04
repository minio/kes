// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"errors"
	"fmt"
	"io"

	"github.com/minio/kes-go"
	"gopkg.in/yaml.v3"
)

func ReadServerConfigYAML(r io.Reader) (*ServerConfig, error) {
	var node yaml.Node
	if err := yaml.NewDecoder(r).Decode(&node); err != nil {
		return nil, err
	}

	version, err := findVersion(&node)
	if err != nil {
		return nil, err
	}
	const Version = "v1"
	if version != "" && version != Version {
		return nil, fmt.Errorf("edge: invalid server config version '%s'", version)
	}

	var y configYML
	if err := node.Decode(&y); err != nil {
		return nil, err
	}
	return ymlToConfig(&y)
}

type ServerConfig struct {
	Addr string

	Admin kes.Identity

	TLS *TLSConfig
}

type TLSConfig struct {
	PrivateKey string

	Certificate string

	CAPath string
}

func findVersion(root *yaml.Node) (string, error) {
	if root == nil {
		return "", errors.New("cluster: invalid server config")
	}
	if root.Kind != yaml.DocumentNode {
		return "", errors.New("cluster: invalid server config")
	}
	if len(root.Content) != 1 {
		return "", errors.New("cluster: invalid server config")
	}

	doc := root.Content[0]
	for i, n := range doc.Content {
		if n.Value == "version" {
			if n.Kind != yaml.ScalarNode {
				return "", fmt.Errorf("cluster: invalid server config version at line '%d'", n.Line)
			}
			if i == len(doc.Content)-1 {
				return "", fmt.Errorf("cluster: invalid server config version at line '%d'", n.Line)
			}
			v := doc.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				return "", fmt.Errorf("cluster: invalid server config version at line '%d'", v.Line)
			}
			return v.Value, nil
		}
	}
	return "", errors.New("cluster: no config version specified")
}
