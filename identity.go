package kes

// IdentityUnknown is the identity returned
// by an IdentityFunc if it cannot map a
// particular X.509 certificate to an actual
// identity.
const IdentityUnknown Identity = ""

// An Identity should uniquely identify a client and
// is computed from the X.509 certificate presented
// by the client during the TLS handshake using an
// IdentityFunc.
type Identity string

// IsUnknown returns true if and only if the
// identity is IdentityUnknown.
func (id Identity) IsUnknown() bool { return id == IdentityUnknown }

// String returns the string representation of
// the identity.
func (id Identity) String() string { return string(id) }
