// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

import (
	"os"
	"strings"
	"time"

	"github.com/minio/kes"
	"gopkg.in/yaml.v3"
)

var ( // compiler checks
	_ yaml.Marshaler   = Identity{}
	_ yaml.Unmarshaler = (*Identity)(nil)

	_ yaml.Marshaler   = String{}
	_ yaml.Unmarshaler = (*String)(nil)

	_ yaml.Marshaler   = Duration{}
	_ yaml.Unmarshaler = (*Duration)(nil)

	_ yaml.Marshaler   = Bool{}
	_ yaml.Unmarshaler = (*Bool)(nil)
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

// Value returns the KES identity.
func (i *Identity) Value() kes.Identity { return i.value }

// Set sets the Identity value.
func (i *Identity) Set(value kes.Identity) { i.value = value }

// MarshalYAML returns the Identity's YAML representation.
func (i Identity) MarshalYAML() (any, error) { return i.raw, nil }

// UnmarshalYAML uses the unmarhsal function to unmarshal
// a YAML block into the Identity.
func (i *Identity) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	i.raw, i.value = raw, kes.Identity(replace(raw))
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

// Value returns the plain string value.
func (s *String) Value() string { return s.value }

// Set sets the String value.
func (s *String) Set(value string) { s.value = value }

// MarshalYAML returns the String's YAML representation.
func (s String) MarshalYAML() (any, error) { return s.raw, nil }

// UnmarshalYAML uses the unmarhsal function to unmarshal
// a YAML block into the String.
func (s *String) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	s.raw, s.value = raw, replace(raw)
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

// Value returns the time duration value.
func (d *Duration) Value() time.Duration { return d.value }

// Set sets the Duration value.
func (d *Duration) Set(value time.Duration) { d.value = value }

// MarshalYAML returns the Duration's YAML representation.
func (d Duration) MarshalYAML() (any, error) { return d.raw, nil }

// UnmarshalYAML uses the unmarhsal function to unmarshal
// a YAML block into the Duration.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	value, err := time.ParseDuration(replace(raw))
	if err != nil {
		return &yaml.TypeError{Errors: []string{err.Error()}}
	}
	d.raw, d.value = raw, value
	return nil
}

// Bool is a YAML bool. It supports YAML
// serialization and deserialization.
//
// During deserialization it replaces env. variable
// references with the corresponding values from
// the environment.
//
// However, it preserves the YAML representation
// and does not serialize any value from the
// environment.
type Bool struct {
	raw   string
	value bool
}

// Value returns the boolean value, either true or false.
func (b *Bool) Value() bool { return b.value }

// Set sets the boolean value.
func (b *Bool) Set(value bool) { b.value = value }

// MarshalYAML returns the Bool's YAML representation.
func (b Bool) MarshalYAML() (any, error) { return b.raw, nil }

// UnmarshalYAML uses the unmarhsal function to unmarshal
// a YAML block into the Bool.
func (b *Bool) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(replace(raw))) {
	case "on", "true":
		b.raw, b.value = raw, true
		return nil
	case "off", "false", "":
		b.raw, b.value = raw, false
		return nil
	default:
		return &yaml.TypeError{Errors: []string{"invalid value for bool"}}
	}
}

func replace(s string) string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}") {
		s = os.ExpandEnv(t)
	}
	return s
}
