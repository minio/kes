package key

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/pelletier/go-toml"
)

const UnknownIdentity Identity = ""

type Identity string

func (id Identity) IsUnknown() bool { return id == UnknownIdentity }

func (id Identity) String() string { return string(id) }

type IdentityFunc func(*x509.Certificate) Identity

func HashPublicKey(hash crypto.Hash) IdentityFunc {
	if !hash.Available() {
		hash = crypto.SHA256
	}
	return func(cert *x509.Certificate) Identity {
		if cert == nil {
			return UnknownIdentity
		}
		h := hash.New()
		h.Write(cert.RawSubjectPublicKeyInfo)
		return Identity(hex.EncodeToString(h.Sum(nil)))
	}
}

const errForbidden policyError = "prohibited by policy"

type policyError string

func (e policyError) Error() string { return string(e) }
func (policyError) Status() int     { return http.StatusForbidden }

type Policy struct {
	patterns []string
}

func (p Policy) MarshalJSON() ([]byte, error) {
	type PolicyJSON struct {
		Patterns []string `json:"paths"`
	}
	return json.Marshal(PolicyJSON{
		Patterns: p.patterns,
	})
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()

	var policyJSON struct {
		Patterns []string `json:"paths"`
	}
	if err := d.Decode(&policyJSON); err != nil {
		return err
	}
	for _, pattern := range policyJSON.Patterns {
		if _, err := path.Match(pattern, ""); err != nil {
			return err
		}
	}
	p.patterns = policyJSON.Patterns
	return nil
}

func (p Policy) MarshalTOML() ([]byte, error) {
	type PolicyTOML struct {
		Patterns []string `toml:"paths"`
	}
	return toml.Marshal(PolicyTOML{
		Patterns: p.patterns,
	})
}

func (p *Policy) UnmarshalTOML(b []byte) error {
	var policyTOML struct {
		Patterns []string `toml:"paths"`
	}

	if err := toml.Unmarshal(b, &policyTOML); err != nil {
		return err
	}
	for _, pattern := range policyTOML.Patterns {
		if _, err := path.Match(pattern, ""); err != nil {
			return err
		}
	}
	p.patterns = policyTOML.Patterns
	return nil
}

func (p *Policy) String() string {
	var builder strings.Builder
	fmt.Fprintln(&builder, "[")
	for _, pattern := range p.patterns {
		fmt.Fprintf(&builder, "  %s\n", pattern)
	}
	fmt.Fprintln(&builder, "]")
	return builder.String()
}

func NewPolicy(patterns ...string) *Policy {
	return &Policy{
		patterns: patterns,
	}
}

func (p *Policy) Verify(r *http.Request) error {
	for _, pattern := range p.patterns {
		if ok, err := path.Match(pattern, r.URL.Path); ok && err == nil {
			return nil
		}
	}
	return errForbidden
}

type Roles struct {
	Root     Identity
	Identify IdentityFunc

	lock           sync.RWMutex
	roles          map[string]*Policy  // all available roles
	effectiveRoles map[Identity]string // identities for which a mapping to a policy name exists
}

func (r *Roles) Set(name string, policy *Policy) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*Policy{}
	}
	r.roles[name] = policy
}

func (r *Roles) Get(name string) (*Policy, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.roles == nil {
		return nil, false
	}
	policy, ok := r.roles[name]
	return policy, ok
}

func (r *Roles) Delete(name string) {
	r.lock.Lock()
	delete(r.roles, name)
	r.lock.Unlock()
}

func (r *Roles) Policies() (names []string) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	names = make([]string, 0, len(r.roles))
	for name := range r.roles {
		names = append(names, name)
	}
	return
}

func (r *Roles) Assign(name string, id Identity) error {
	if id == r.Root {
		return errors.New("key: identity is root")
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	if r.roles == nil {
		r.roles = map[string]*Policy{}
	}
	_, ok := r.roles[name]
	if !ok {
		return errors.New("key: policy does not exists")
	}
	if r.effectiveRoles == nil {
		r.effectiveRoles = map[Identity]string{}
	}
	r.effectiveRoles[id] = name
	return nil
}

func (r *Roles) IsAssigned(id Identity) bool {
	if id == r.Root {
		return true
	}

	r.lock.RLock()
	defer r.lock.RUnlock()

	if r.effectiveRoles != nil {
		if name, ok := r.effectiveRoles[id]; ok {
			_, ok = r.roles[name]
			return ok
		}
	}
	return false
}

func (r *Roles) Identities() map[Identity]string {
	r.lock.RLock()
	defer r.lock.RUnlock()

	identities := make(map[Identity]string, len(r.effectiveRoles))
	for id, policy := range r.effectiveRoles {
		identities[id] = policy
	}
	return identities
}

func (r *Roles) Forget(id Identity) {
	r.lock.Lock()
	delete(r.effectiveRoles, id)
	r.lock.Unlock()
}

func (r *Roles) enforce(req *http.Request) error {
	if req.TLS == nil {
		return nil // TODO: decide
	}

	if len(req.TLS.PeerCertificates) > 1 {
		return policyError("too many identities: more than one certificate is present")
	}

	var cert *x509.Certificate
	if len(req.TLS.PeerCertificates) > 0 {
		cert = req.TLS.PeerCertificates[0]
	}

	var identity Identity
	if r.Identify == nil {
		identity = defaultIdentify(cert)
	} else {
		identity = r.Identify(cert)
	}
	if identity == r.Root {
		return nil
	}

	var policy *Policy
	r.lock.RLock()
	if r.roles != nil && r.effectiveRoles != nil {
		if name, ok := r.effectiveRoles[identity]; ok {
			policy = r.roles[name]
		}
	}
	r.lock.RUnlock()

	if policy == nil {
		return errForbidden
	}
	return policy.Verify(req)
}

func defaultIdentify(cert *x509.Certificate) Identity {
	if cert == nil {
		return UnknownIdentity
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return Identity(hex.EncodeToString(h[:]))
}
