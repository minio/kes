// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"encoding"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/minio/kes-go"
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
type Env[T string | kes.Identity | time.Duration] struct {
	Name  string // Name of the env. variable
	Value T      // Value obtained by unmarshalling or from the environment
}

// For now we limit Env[T] to:
// - string
// - kes.Identity
// - time.Duration
//
// It is possible to add more types in the future (e.g. net.IP, url.URL, ...)
// and relax the constraints further (e.g. ~string or ~int64). However,
// this has implications for marshaling and esp. unmarshaling.
//
// For marshaling we can get away with some reasonable interface checks.
// For example fmt.Stringer and encoding.TextMarshaler.
// However, unmarshalling semantics are complex. For example, we could allow
// Env for any type based on int64 via `~int64` - including time.Duration.
// But we want to unmarshal a time.Duration via time.ParseDuration, not via
// strconv.ParseInt64. For other types we just don't know whether there is
// a specialised parse function or whether ParseInt64 should be used.
//
// The current implementation is very primitive but good enough
// for the moment.

// MarshalText returns a text representation of the Env[T].
//
// If Env[T] refers to an environment variable then MarshalText
// returns the environment variable name as "${variable}".
// Otherwise, it returns a text representation of T.
func (e Env[_]) MarshalText() ([]byte, error) {
	if name := strings.TrimSpace(e.Name); name != "" {
		switch hasPrefix, hasSuffix := strings.HasPrefix(name, "${"), strings.HasSuffix(name, "}"); {
		case hasPrefix && hasSuffix:
			return []byte(name), nil
		case !hasPrefix && !hasSuffix:
			return []byte("${" + name + "}"), nil
		default:
			return nil, errors.New("keserv: invalid env variable name '" + e.Name + "'")
		}
	}
	return marshalText(e.Value)
}

// UnmarshalText parses the text as Env[T].
//
// If the given text refers to an environment variable then
// UnmarshalText looks up the value from the environment.
// It returns an error if no such environment variable exists.
//
// Otherwise, it parses the text as T and sets the Env[T] name
// to the empty string.
func (e *Env[_]) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	switch hasPrefix, hasSuffix := strings.HasPrefix(s, "${"), strings.HasSuffix(s, "}"); {
	case hasPrefix && hasSuffix:
		name := strings.TrimSuffix(strings.TrimPrefix(s, "${"), "}")
		value, ok := os.LookupEnv(name)
		if !ok {
			return errors.New("keserv: env variable '" + name + "' not found")
		}
		if err := unmarshalText([]byte(value), &e.Value); err != nil {
			return err
		}
		e.Name = name
		return nil
	case !hasPrefix && !hasSuffix:
		if err := unmarshalText(text, &e.Value); err != nil {
			return err
		}
		e.Name = ""
		return nil
	default:
		return errors.New("keserv: invalid env variable name '" + s + "'")
	}
}

func marshalText(v any) ([]byte, error) {
	switch v := v.(type) {
	case encoding.TextMarshaler:
		return v.MarshalText()
	case string:
		return []byte(v), nil
	case time.Duration:
		return []byte(v.String()), nil
	case kes.Identity:
		return []byte(v.String()), nil
	default: // Go compiler ensures via type constraints that this never happens
		panic(fmt.Sprintf("keserv: cannot marshal unsupported type %T", v))
	}
}

func unmarshalText(text []byte, v any) error {
	switch v := v.(type) {
	case encoding.TextUnmarshaler:
		return v.UnmarshalText(text)
	case *string:
		*v = string(text)
		return nil
	case *kes.Identity:
		*v = kes.Identity(text)
		return nil
	case *time.Duration:
		d, err := time.ParseDuration(string(text))
		if err != nil {
			return err
		}
		*v = d
		return nil
	default: // Go compiler ensures via type constraints that this never happens
		panic(fmt.Sprintf("keserv: cannot unmarshal unsupported type %T", v))
	}
}
