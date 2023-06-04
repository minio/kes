// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto

import (
	"errors"
	"math"
	"strconv"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/msgp"
)

// MaxSecretSize represents the maximum size of a secret in bytes.
const MaxSecretSize = 1 * mem.MB

// MaxSecretVersions specifies the maximum number of concurrent
// versions for a secret.
const MaxSecretVersions = 10000

// SecretType represents the type of secret.
type SecretType uint

// Secret types.
const (
	// SecretTypeGeneric represents a generic secret.
	SecretTypeGeneric SecretType = iota
)

// Secret represents a collection of secret versions.
type Secret struct {
	versions  map[uint32]SecretVersion
	n, latest uint32
}

// Latest returns the latest secret version and its corresponding
// version number.
func (s *Secret) Latest() (SecretVersion, uint32) { return s.versions[s.latest], s.latest }

// Get retrieves a specific secret version based on its version number.
// It returns false if the version does not exist.
func (s *Secret) Get(version uint32) (SecretVersion, bool) {
	v, ok := s.versions[version]
	return v, ok
}

// Add adds a new secret version to the secret.
//
// In total, at most 2^32 - 1 versions can be added to
// a secret. Once this limit has been, reached no more
// versions can be added.
//
// A secret can hold up to MaxSecretVersions at the
// same time. Once its max. capacity has been reached,
// secret versions must be removed before new versions
// can be added again.
func (s *Secret) Add(version SecretVersion) error {
	if s.latest == math.MaxUint32 {
		return errors.New("crypto: no more secret versions available")
	}
	if len(s.versions) >= MaxSecretVersions {
		return errors.New("crypto: too many secret versions")
	}

	if s.versions == nil {
		s.versions = make(map[uint32]SecretVersion)
	}
	s.versions[s.n] = version
	s.latest = s.n
	s.n++
	return nil
}

// Remove removes a specific secret version.
func (s *Secret) Remove(version uint32) bool {
	if _, ok := s.versions[version]; !ok {
		return false
	}
	delete(s.versions, version)

	if version == s.latest {
		if _, ok := s.versions[s.latest-1]; ok {
			s.latest--
			return true
		}

		var max uint32
		for version := range s.versions {
			if version > max {
				max = version
			}
		}
		s.latest = max
	}
	return true
}

// MarshalMsg converts the Secret into its MessagePack representation.
func (s *Secret) MarshalMsg() (msgp.Secret, error) {
	versions := make(map[string]msgp.SecretVersion, len(s.versions))
	for k, v := range s.versions {
		version, err := v.MarshalMsg()
		if err != nil {
			return msgp.Secret{}, err
		}
		versions[strconv.Itoa(int(k))] = version
	}
	return msgp.Secret{
		Versions: versions,
		N:        s.n,
		Latest:   s.latest,
	}, nil
}

// UnmarshalMsg initializes the Secret from its MessagePack representation.
func (s *Secret) UnmarshalMsg(v *msgp.Secret) error {
	versions := make(map[uint32]SecretVersion, len(v.Versions))
	for ver, sec := range v.Versions {
		version, err := strconv.Atoi(ver)
		if err != nil {
			return err
		}
		if version > math.MaxUint32 {
			return errors.New("crypto: secret version overflow")
		}

		var secret SecretVersion
		if err = secret.UnmarshalMsg(&sec); err != nil {
			return err
		}
		versions[uint32(version)] = secret
	}

	s.versions = versions
	s.n = v.N
	s.latest = v.Latest
	return nil
}

// SecretVersion represents a version of a secret.
type SecretVersion struct {
	Value     []byte       // The value of the secret
	Type      SecretType   // The type of the secret
	CreatedAt time.Time    // The creation timestamp of the secret version
	CreatedBy kes.Identity // The identity of the entity that created the secret version
}

// MarshalMsg converts the SecretVersion into its MessagePack representation.
func (s *SecretVersion) MarshalMsg() (msgp.SecretVersion, error) {
	return msgp.SecretVersion{
		Value:     s.Value,
		Type:      uint(s.Type),
		CreatedAt: s.CreatedAt,
		CreatedBy: s.CreatedBy.String(),
	}, nil
}

// UnmarshalMsg initializes the SecretVersion from its MessagePack representation.
func (s *SecretVersion) UnmarshalMsg(v *msgp.SecretVersion) error {
	s.Value = v.Value
	s.Type = SecretType(v.Type)
	s.CreatedAt = v.CreatedAt
	s.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}
