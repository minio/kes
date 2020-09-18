// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
)

const keyCmdUsage = `usage: %s <command>

    create               Create a new secret key at a kes server.
    delete               Delete a secret key from a kes server.

    derive               Derive a new key from a secret key.
    decrypt              Decrypt an encrypted key with a secret key.

  -h, --help             Show this list of command line options.
`

func key(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), keyCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "create":
		return createKey(args)
	case "delete":
		return deleteKey(args)
	case "derive":
		return deriveKey(args)
	case "decrypt":
		return decryptKey(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}
