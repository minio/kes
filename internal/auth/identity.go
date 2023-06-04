// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package auth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/hashset"
	"github.com/minio/kes/internal/msgp"
)

func IdentifyRequest(state *tls.ConnectionState) (kes.Identity, error) {
	if state == nil {
		return "", kes.NewError(http.StatusBadRequest, "insecure connection: TLS is required")
	}

	var cert *x509.Certificate
	for _, c := range state.PeerCertificates {
		if c.IsCA {
			continue
		}
		if cert != nil {
			return "", kes.NewError(http.StatusBadRequest, "tls: received more than one client certificate")
		}
		cert = c
	}
	if cert == nil {
		return "", kes.NewError(http.StatusBadRequest, "tls: client certificate is required")
	}

	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return kes.Identity(hex.EncodeToString(h[:])), nil
}

const MaxChildren = 1000

type Identity struct {
	Identity  kes.Identity
	Policy    string
	IsAdmin   bool
	Children  hashset.Set[kes.Identity]
	TTL       time.Duration
	ExpiresAt time.Time
	CreatedAt time.Time
	CreatedBy kes.Identity
}

func (i *Identity) MarshalMsg() (msgp.Identity, error) {
	children := make([]string, 0, i.Children.Len())
	for child := range i.Children.Values() {
		children = append(children, child.String())
	}
	return msgp.Identity{
		Policy:    i.Policy,
		IsAdmin:   i.IsAdmin,
		Children:  children,
		ExpiresAt: i.ExpiresAt,
		TTL:       i.TTL,
		CreatedAt: i.CreatedAt,
		CreatedBy: i.CreatedBy.String(),
	}, nil
}

func (i *Identity) UnmarshalMsg(v *msgp.Identity) error {
	children := hashset.NewSet[kes.Identity](len(v.Children))
	for _, child := range v.Children {
		children.Add(kes.Identity(child))
	}
	i.Policy = v.Policy
	i.IsAdmin = v.IsAdmin
	i.TTL = v.TTL
	i.Children = children
	i.ExpiresAt = v.ExpiresAt
	i.CreatedAt = v.CreatedAt
	i.CreatedBy = kes.Identity(v.CreatedBy)
	return nil
}
