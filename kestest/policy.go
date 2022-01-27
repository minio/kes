// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
)

// PolicySet holds a set of KES policies and
// the identity-policy associations.
type PolicySet struct {
	roles *auth.Roles
}

// Admin returns the admin Identity that can
// perform any KES API operation.
func (p *PolicySet) Admin() kes.Identity { return p.roles.Root }

// Add adds the given KES policy to the PolicySet.
// Any existing policy with the same name is replaced.
func (p *PolicySet) Add(name string, policy *kes.Policy) { p.roles.Set(name, policy) }

// Allow adds a new KES policy that allows the given API
// patterns to the PolicySet.
//
// Allow is a shorthand for first creating a KES Policy
// and then adding it to the PolicySet.
func (p *PolicySet) Allow(name string, patterns ...string) {
	policy, err := kes.NewPolicy(patterns...)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to create policy: %v", err))
	}
	p.Add(name, policy)
}

// Assign assigns the KES policy with the given name to
// all given identities.
//
// It returns the first error encountered when assigning
// identities, if any.
func (p *PolicySet) Assign(name string, ids ...kes.Identity) error {
	for _, id := range ids {
		if err := p.roles.Assign(name, id); err != nil {
			return fmt.Errorf("kestest: failed to assign policy %q to %q: %v", name, id, err)
		}
	}
	return nil
}

// Identify returns the Identity of the TLS certificate.
//
// It computes the Identity as fingerprint of the
// X.509 leaf certificate.
func Identify(cert *tls.Certificate) kes.Identity {
	if cert.Leaf == nil {
		var err error
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			panic(fmt.Sprintf("kestest: failed to parse X.509 certificate: %v", err))
		}
	}

	id := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(id[:]))
}
