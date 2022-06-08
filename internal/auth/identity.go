// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/minio/kes"
)

// ErrIdentityNotFound is returned by an IdentitySet if a specified
// identity does not exist.
var ErrIdentityNotFound = kes.NewError(http.StatusNotFound, "identity does not exist")

// Identify computes the identity of the given HTTP request.
//
// If the request was not sent over TLS or no client
// certificate has been provided, Identify returns
// IdentityUnknown.
func Identify(req *http.Request) kes.Identity {
	if req.TLS == nil {
		return kes.IdentityUnknown
	}

	var cert *x509.Certificate
	for _, c := range req.TLS.PeerCertificates {
		if c.IsCA {
			continue // Ignore CA certificates
		}

		if cert != nil {
			// There is more than one client certificate
			// that is not a CA certificate. Hence, we
			// cannot compute an non-ambiguous identity.
			// Therefore, we return IdentityUnknown.
			return kes.IdentityUnknown
		}
		cert = c
	}
	if cert == nil {
		return kes.IdentityUnknown
	}

	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(h[:]))
}

// An IdentitySet is a set of identities that are assigned to policies.
type IdentitySet interface {
	// Admin returns the identity of the admin.
	//
	// The admin is never assigned to any policy
	// and can perform any operation.
	Admin(ctx context.Context) (kes.Identity, error)

	// SetAdmin sets the identity of the admin.
	//
	// The admin is never assigned to any policy
	// and can perform any operation.
	SetAdmin(ctx context.Context, admin kes.Identity) error

	// Assign assigns the policy to the given identity.
	//
	// It returns an error when the identity is equal
	// to the admin identity.
	Assign(ctx context.Context, policy string, identity kes.Identity) error

	// Get returns the IdentityInfo of an assigned identity.
	//
	// It returns ErrIdentityNotFound when there is no IdentityInfo
	// associated to the given identity.
	Get(ctx context.Context, identity kes.Identity) (IdentityInfo, error)

	// Delete deletes the given identity from the list of
	// assigned identites.
	//
	// It returns ErrNotAssigned when the identity is not
	// assigned.
	Delete(ctx context.Context, identity kes.Identity) error

	// List returns an iterator over all assigned identities.
	List(ctx context.Context) (IdentityIterator, error)
}

// An IdentityIterator iterates over a list of identites.
//   for iterator.Next() {
//       _ = iterator.Identity() // Get the next identity
//   }
//   if err := iterator.Close(); err != nil {
//   }
//
// Once done iterating, an IdentityIterator should be closed.
//
// In general, an IdentityIterator does not provide any
// ordering guarantees. Concurrent changes to the underlying
// source may not be reflected by the iterator.
type IdentityIterator interface {
	// Next moves the iterator to the subsequent identity, if any.
	// This identity is available until Next is called again.
	//
	// It returns true if and only if there is another identity.
	// Once an error occurs or once there are no more identities,
	// Next returns false.
	Next() bool

	// Identity returns the current identity. Identity can be
	// called multiple times and returns the same value until
	// Next is called again.
	Identity() kes.Identity

	// Close closes the iterator and releases resources. It
	// returns any error encountered while iterating, if any.
	// Otherwise, it returns any error that occurred while
	// closing, if any.
	Close() error
}

// IdentityInfo describes an assigned identity.
type IdentityInfo struct {
	// Policy is the policy the identity is assigned to.
	Policy string

	// IsAdmin indicates whether the identity has admin
	// privileges.
	IsAdmin bool

	// CreatedAt is the point in time when the identity
	// has been assigned.
	CreatedAt time.Time

	// CreatedBy is the identity that assigned this
	// identity to its policy.
	CreatedBy kes.Identity
}

// MarshalBinary returns the IdentityInfo's binary representation.
func (i IdentityInfo) MarshalBinary() ([]byte, error) {
	type GOB struct {
		Policy    string
		IsAdmin   bool
		CreatedAt time.Time
		CreatedBy kes.Identity
	}

	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(GOB(i)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalBinary unmarshals the IdentityInfo's binary representation.
func (i *IdentityInfo) UnmarshalBinary(b []byte) error {
	type GOB struct {
		Policy    string
		IsAdmin   bool
		CreatedAt time.Time
		CreatedBy kes.Identity
	}

	var value GOB
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&value); err != nil {
		return err
	}
	i.Policy = value.Policy
	i.IsAdmin = value.IsAdmin
	i.CreatedAt = value.CreatedAt
	i.CreatedBy = value.CreatedBy
	return nil
}
