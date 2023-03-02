// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Env wraps a type T and an optional environment
// variable name.
//
// It can be used to replace env. variable references
// with values from the environment during unmarshalling.
// Further, Env preserves any env. variable references
// during marshaling.
//
// During unmarshalling, Env replaces T's value
// with the value obtained from the referenced
// environment variable, if any.
//
// During marshaling, Env preserves and encodes
// the env. variable reference, if not empty.
// Otherwise, it encodes Env generic type value.
type Env[T any] struct {
	Name  string // Name of the env. variable
	Value T      // Value obtained by unmarshalling or from the environment
}

// MarshalYAML returns the Env[T]'s YAML representation.
//
// If Env[T] refers to an environment variable then MarshalYAML
// returns the environment variable name as "${name}".
// Otherwise, it returns the YAML representation of T.
func (e Env[_]) MarshalYAML() (any, error) {
	if e.Name != "" {
		name := strings.TrimSpace(e.Name)
		switch hasPrefix, hasSuffix := strings.HasPrefix(name, "${"), strings.HasSuffix(name, "}"); {
		case hasPrefix && hasSuffix:
			return name, nil
		case !hasPrefix && !hasSuffix:
			return "${" + name + "}", nil
		default:
			return nil, errors.New("keserv: invalid env variable name '" + e.Name + "'")
		}
	}
	return e.Value, nil
}

// UnmarshalYAML decodes the YAML node into the Env[T].
//
// If the YAML node refers to an environment variable then
// UnmarshalYAML first looks up the value from the environment
// before unmarshaling it.
func (e *Env[_]) UnmarshalYAML(node *yaml.Node) error {
	if name := strings.TrimSpace(node.Value); strings.HasPrefix(name, "${") && strings.HasSuffix(name, "}") {
		name = strings.TrimSpace(name[2 : len(name)-1]) // We know that there is a '${' prefix and '}' suffix
		value, ok := os.LookupEnv(name)
		if !ok {
			return fmt.Errorf("keserv: line %d: env. variable '%s' not found", node.Line, name)
		}

		node.Value = value
		if err := node.Decode(&e.Value); err != nil {
			return err
		}
		e.Name = name
		return nil
	}
	if err := node.Decode(&e.Value); err != nil {
		return err
	}
	e.Name = ""
	return nil
}
