// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kestest_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"

	"github.com/minio/kes"
	"github.com/minio/kes/kestest"
)

func ExampleServer() {
	var server = kestest.NewServer()
	defer server.Close()

	version, err := server.Client().Version(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(version)

	// Output:
	// v0.0.0-dev
}

func ExampleServer_IssueClientCertificate() {
	var server = kestest.NewServer()
	defer server.Close()

	server.Policy().Allow("test-policy",
		"/v1/key/create/*",
		"/v1/key/generate/*",
		"/v1/key/decrypt/*",
	)

	var (
		clientCert = server.IssueClientCertificate("test-client")
		client     = kes.NewClientWithConfig(server.URL, &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      server.CAs(),
		})
	)
	server.Policy().Assign("test-policy", kestest.Identify(&clientCert))

	if err := client.CreateKey(context.Background(), "test-key"); err != nil {
		log.Fatal(err)
	}
	if err := client.DeleteKey(context.Background(), "test-key"); err != kes.ErrNotAllowed {
		log.Fatalf("Deleting a key did not fail with %v", kes.ErrNotAllowed)
	}
	// Output:
	//
}
