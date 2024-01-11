// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"errors"
	"strconv"

	"gopkg.in/yaml.v3"
)

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
