// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
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

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	if len(bytes) > 0 {
		if err = client.ImportKey(name, bytes); err != nil {
			return fmt.Errorf("Failed to import %s: %v", name, err)
		}
	} else {
		if err = client.CreateKey(name); err != nil {
			return fmt.Errorf("Failed to create %s: %v", name, err)
		}
	}
	return nil
}
