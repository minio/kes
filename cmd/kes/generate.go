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

const generateCmdUsage = `usage: %s name [context]

  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func deriveKey(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), generateCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 1 && len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	var (
		name    string = args[0]
		context []byte
	)
	if len(args) == 2 {
		b, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return fmt.Errorf("Invalid context: %v", err)
		}
		context = b
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	key, err := client.GenerateKey(name, context)
	if err != nil {
		return fmt.Errorf("Failed to generate data key: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Println("{")
		fmt.Printf("  plaintext : %s\n", base64.StdEncoding.EncodeToString(key.Plaintext))
		fmt.Printf("  ciphertext: %s\n", base64.StdEncoding.EncodeToString(key.Ciphertext))
		fmt.Println("}")
	} else {
		const format = `{"plaintext":"%s","ciphertext":"%s"}`
		fmt.Printf(format, base64.StdEncoding.EncodeToString(key.Plaintext), base64.StdEncoding.EncodeToString(key.Ciphertext))
	}
	return nil
}
