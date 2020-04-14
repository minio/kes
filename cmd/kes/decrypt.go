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

const decryptCmdUsage = `usage: %s <name> <ciphertext> [<context>]

  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func decryptKey(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), decryptCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 2 && len(args) != 3 {
		cli.Usage()
		os.Exit(2)
	}

	var (
		name       string = args[0]
		ciphertext []byte
		context    []byte
		err        error
	)
	ciphertext, err = base64.StdEncoding.DecodeString(args[1])
	if err != nil {
		return fmt.Errorf("Invalid ciphertext: %v", err)
	}
	if len(args) == 3 {
		context, err = base64.StdEncoding.DecodeString(args[2])
		if err != nil {
			return fmt.Errorf("Invalid context: %v", err)
		}
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	plaintext, err := client.Decrypt(name, ciphertext, context)
	if err != nil {
		return fmt.Errorf("Failed to decrypt data key: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\n  plaintext: %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		fmt.Printf(`{"plaintext":"%s"}`, base64.StdEncoding.EncodeToString(plaintext))
	}
	return nil
}
