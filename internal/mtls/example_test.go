// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package mtls_test

import (
	"crypto/tls"
	"log"

	"github.com/minio/kes/internal/mtls"
)

func ExampleWithServerCertificate() {
	const (
		CertFile = "./testdata/certificates/example.crt"
		KeyFile  = "./testdata/privatekeys/example.key"
		Password = "" // Private key is not encrypted
		Host     = "example.com"
	)

	options := []mtls.Option{
		mtls.WithServerCertificate(CertFile, KeyFile, Password, Host),
	}
	config := &tls.Config{}
	for _, opt := range options {
		if err := opt(config); err != nil {
			log.Fatal(err)
		}
	}
	// Output:
}

func ExampleWithRootCAs() {
	const CAPath = "./testdata/ca"

	options := []mtls.Option{
		mtls.WithRootCAs(CAPath),
	}
	config := &tls.Config{}
	for _, opt := range options {
		if err := opt(config); err != nil {
			log.Fatal(err)
		}
	}
	// Output:
}
