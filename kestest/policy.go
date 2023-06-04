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

	"github.com/minio/kes-go"
)

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
