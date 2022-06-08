// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
)

// PolicySet holds a set of KES policies and
// the identity-policy associations.
type PolicySet struct {
	admin      kes.Identity
	policies   map[string]*auth.Policy
	identities map[kes.Identity]auth.IdentityInfo
}

// Admin returns the admin Identity that can
// perform any KES API operation.
func (p *PolicySet) Admin() kes.Identity { return p.admin }

// Add adds the given KES policy to the PolicySet.
// Any existing policy with the same name is replaced.
func (p *PolicySet) Add(name string, policy *kes.Policy) {
	p.policies[name] = &auth.Policy{
		Allow: policy.Allow,
		Deny:  policy.Deny,
	}
}

// Allow adds a new KES policy that allows the given API
// patterns to the PolicySet.
//
// Allow is a shorthand for first creating a KES Policy
// and then adding it to the PolicySet.
func (p *PolicySet) Allow(name string, patterns ...string) {
	p.Add(name, &kes.Policy{Allow: patterns})
}

// Assign assigns the KES policy with the given name to
// all given identities.
//
// It returns the first error encountered when assigning
// identities, if any.
func (p *PolicySet) Assign(name string, ids ...kes.Identity) error {
	for _, id := range ids {
		if id.IsUnknown() {
			return fmt.Errorf("kestest: failed to assign policy %q to %q: identity is empty", name, id)
		}
		if id == p.Admin() {
			return fmt.Errorf("kestest: failed to assign policy %q to %q: equal to admin identity", name, id)
		}
		p.identities[id] = auth.IdentityInfo{
			Policy:    name,
			CreatedAt: time.Now().UTC(),
			CreatedBy: p.admin,
		}
	}
	return nil
}

func (p *PolicySet) policySet() auth.PolicySet {
	return &policySet{
		policies: p.policies,
	}
}

func (p *PolicySet) identitySet() auth.IdentitySet {
	return &identitySet{
		admin:     p.admin,
		createdAt: time.Now().UTC(),
		roles:     p.identities,
	}
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

type policySet struct {
	lock     sync.RWMutex
	policies map[string]*auth.Policy
}

func (p *policySet) Set(_ context.Context, name string, policy *auth.Policy) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.policies[name] = policy
	return nil
}

func (p *policySet) Get(_ context.Context, name string) (*auth.Policy, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	policy, ok := p.policies[name]
	if !ok {
		return nil, kes.ErrPolicyNotFound
	}
	return policy, nil
}

func (p *policySet) Delete(_ context.Context, name string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.policies, name)
	return nil
}

func (p *policySet) List(_ context.Context) (auth.PolicyIterator, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	names := make([]string, 0, len(p.policies))
	for name := range p.policies {
		names = append(names, name)
	}
	return &policyIterator{
		values: names,
	}, nil
}

type policyIterator struct {
	values  []string
	current string
}

func (i *policyIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *policyIterator) Name() string { return i.current }

func (i *policyIterator) Close() error { return nil }

type identitySet struct {
	admin     kes.Identity
	createdAt time.Time

	lock  sync.RWMutex
	roles map[kes.Identity]auth.IdentityInfo
}

func (i *identitySet) Admin(ctx context.Context) (kes.Identity, error) { return i.admin, nil }

func (i *identitySet) SetAdmin(context.Context, kes.Identity) error {
	return kes.NewError(http.StatusNotImplemented, "cannot set admin identity")
}

func (i *identitySet) Assign(_ context.Context, policy string, identity kes.Identity) error {
	if i.admin == identity {
		return kes.NewError(http.StatusBadRequest, "identity is root")
	}
	i.lock.Lock()
	defer i.lock.Unlock()

	i.roles[identity] = auth.IdentityInfo{
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

func (i *identitySet) Get(_ context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if identity == i.admin {
		return auth.IdentityInfo{
			IsAdmin:   true,
			CreatedAt: i.createdAt,
		}, nil
	}
	i.lock.RLock()
	defer i.lock.RUnlock()

	policy, ok := i.roles[identity]
	if !ok {
		return auth.IdentityInfo{}, auth.ErrIdentityNotFound
	}
	return policy, nil
}

func (i *identitySet) Delete(_ context.Context, identity kes.Identity) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	delete(i.roles, identity)
	return nil
}

func (i *identitySet) List(_ context.Context) (auth.IdentityIterator, error) {
	i.lock.RLock()
	defer i.lock.RUnlock()

	values := make([]kes.Identity, 0, len(i.roles))
	for identity := range i.roles {
		values = append(values, identity)
	}
	return &identityIterator{
		values: values,
	}, nil
}

type identityIterator struct {
	values  []kes.Identity
	current kes.Identity
}

func (i *identityIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *identityIterator) Identity() kes.Identity { return i.current }

func (i *identityIterator) Close() error { return nil }
