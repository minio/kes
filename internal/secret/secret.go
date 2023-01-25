// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"bytes"
	"encoding/gob"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
)

// MaxSize is the maximum size of a secret.
const MaxSize = 1 * mem.MiB

// Secret is a generic secret, like a password,
// API key, or private key.
type Secret struct {
	kind      kes.SecretType
	createdAt time.Time
	modTime   time.Time
	createdBy kes.Identity

	bytes []byte
}

// NewSecret returns a new generic Secret from the given
// value.
//
// Its CreatedAt timestamp is time.Now and its CreatedBy
// identity is the owner.
func NewSecret(value []byte, owner kes.Identity) Secret {
	now := time.Now().UTC()
	return Secret{
		bytes:     clone(value),
		kind:      kes.SecretGeneric,
		createdAt: now,
		modTime:   now,
		createdBy: owner,
	}
}

// Type returns the Secret's type.
func (s *Secret) Type() kes.SecretType { return s.kind }

// CreatedAt returns the point in time when the secret has
// been created.
func (s *Secret) CreatedAt() time.Time { return s.createdAt }

// ModTime returns the most recent point in time at which
// the secret has been modified. If the secret has never
// been modified, its ModTime is equal to its CreatedAt
// time.
func (s *Secret) ModTime() time.Time { return s.modTime }

// CreatedBy returns the identity that created the secret.
func (s *Secret) CreatedBy() kes.Identity { return s.createdBy }

// Bytes returns the Secret value.
func (s *Secret) Bytes() []byte { return clone(s.bytes) }

// MarshalBinary returns the Secret's binary representation.
func (s *Secret) MarshalBinary() ([]byte, error) {
	type GOB struct {
		Type      kes.SecretType
		CreatedAt time.Time
		ModTime   time.Time
		CreatedBy kes.Identity
		Bytes     []byte
	}

	var buffer bytes.Buffer
	err := gob.NewEncoder(&buffer).Encode(GOB{
		Type:      s.kind,
		Bytes:     s.bytes,
		CreatedAt: s.CreatedAt(),
		ModTime:   s.modTime,
		CreatedBy: s.CreatedBy(),
	})
	return buffer.Bytes(), err
}

// UnmarshalBinary unmarshals the Secret's binary representation.
func (s *Secret) UnmarshalBinary(data []byte) error {
	type GOB struct {
		Type      kes.SecretType
		CreatedAt time.Time
		ModTime   time.Time
		CreatedBy kes.Identity
		Bytes     []byte
	}

	var value GOB
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&value); err != nil {
		return err
	}

	s.kind = value.Type
	s.bytes = value.Bytes
	s.createdAt = value.CreatedAt
	s.modTime = value.ModTime
	s.createdBy = value.CreatedBy
	return nil
}

// Iter is an iterator over secrets.
type Iter interface {
	// Next fetches the next secret entry. It returns
	// false when there are no more entries or once it
	// encounters an error.
	//
	// Once Next returns false, it returns false on any
	// subsequent Next call.
	Next() bool

	// Name returns the name of the latest fetched entry.
	// It returns the same name until Next is called again.
	//
	// As long as Next hasn't been called once or once Next
	// returns false, Name returns the empty string.
	Name() string

	// Close closes the Iter. Once closed, any subsequent
	// Next call returns false.
	//
	// Close returns the first error encountered while iterating
	// over the entires, if any. Otherwise, it returns the error
	// encountered while cleaning up any resources, if any.
	// Subsequent calls to Close return the same error.
	Close() error
}

func clone(data []byte) []byte { return append(make([]byte, 0, len(data)), data...) }
