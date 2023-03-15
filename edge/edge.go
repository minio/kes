// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ReadServerConfigYAML returns a new ServerConfig unmarshalled
// from the YAML read from r.
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

	var y yml
	if err := node.Decode(&y); err != nil {
		return nil, err
	}
	return ymlToServerConfig(&y)
}
