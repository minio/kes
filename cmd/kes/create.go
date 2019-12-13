// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/minio/kes"
)

const createCmdUsage = `usage: %s name [key]

  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func createKey(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), createCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 1 && len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	var (
		name  string = args[0]
		bytes []byte
	)
	if len(args) == 2 {
		b, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("Invalid key: %v", err)
		}
		bytes = b
	}

	certificates, err := loadClientCertificates()
	if err != nil {
		return err
	}
	client := kes.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       certificates,
	})

	if err := client.CreateKey(name, bytes); err != nil {
		return fmt.Errorf("Failed to create %s: %v", name, err)
	}
	return nil
}
