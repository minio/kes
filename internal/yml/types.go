// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

import (
	"os"
	"strings"
	"time"

	"github.com/minio/kes"
	"gopkg.in/yaml.v2"
)

// Identity is a KES identity. It supports YAML
// serialization and deserialization.
//
// During deserialization it replaces env. variable
// references with the corresponding values from
// the environment.
//
// However, it preserves the YAML representation
// and does not serialize any value from the
// environment.
type Identity struct {
	raw   string
	value kes.Identity
}

var ( // compiler check
	_ yaml.Marshaler   = Identity{}
	_ yaml.Unmarshaler = (*Identity)(nil)
)

// Value returns the KES identity.
func (i *Identity) Value() kes.Identity { return i.value }

func (i Identity) MarshalYAML() (interface{}, error) { return i.raw, nil }

func (i *Identity) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	i.raw, i.value = raw, kes.Identity(replace(raw, os.Getenv))
	return nil
}

// String is a YAML string. It supports YAML
// serialization and deserialization.
//
// During deserialization it replaces env. variable
// references with the corresponding values from
// the environment.
//
// However, it preserves the YAML representation
// and does not serialize any value from the
// environment.
type String struct {
	raw   string
	value string
}

var ( // compiler check
	_ yaml.Marshaler   = String{}
	_ yaml.Unmarshaler = (*String)(nil)
)

// Value returns the plain string value.
func (s *String) Value() string { return s.value }

func (s *String) Set(v string) { s.value = v }

func (s String) MarshalYAML() (interface{}, error) { return s.raw, nil }

func (s *String) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	s.raw, s.value = raw, replace(raw, os.Getenv)
	return nil
}

// A Duration represents the elapsed time between two instants
// as an int64 nanosecond count. The representation limits the
// largest representable duration to approximately 290 years.
//
// It supports YAML serialization and deserialization.
//
// During deserialization it replaces env. variable references
// with the corresponding values from the environment.
//
// However, it preserves the YAML representation and does not
// serialize any value from the environment.
type Duration struct {
	raw   string
	value time.Duration
}

var ( // compiler check
	_ yaml.Marshaler   = Duration{}
	_ yaml.Unmarshaler = (*Duration)(nil)
)

// Value returns the time duration value.
func (d *Duration) Value() time.Duration { return d.value }

func (d Duration) MarshalYAML() (interface{}, error) { return d.raw, nil }

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	value, err := time.ParseDuration(replace(raw, os.Getenv))
	if err != nil {
		return &yaml.TypeError{Errors: []string{err.Error()}}
	}
	d.raw, d.value = raw, value
	return nil
}

func replace(s string, mapping func(string) string) string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}") {
		s = os.Expand(t, mapping)
	}
	return s
}
