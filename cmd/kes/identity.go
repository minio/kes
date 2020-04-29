// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/minio/kes"
)

const identityCmdUsage = `usage: %s <command>
  
  assign               Assign an identity to a policy.
  list                 List identities at the KES server.
  forget               Forget an identity.

  -h, --help           Show list of command-line options
`

func identity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), identityCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "assign":
		return assignIdentity(args)
	case "list":
		return listIdentity(args)
	case "forget":
		return forgetIdentity(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}

const assignIdentityCmdUsage = `usage: %s <identity> <policy>

  -k, --insecure       Skip X.509 certificate validation during TLS handshake  

  -h, --help           Show list of command-line options
`

func assignIdentity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), assignIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	if err := client.AssignIdentity(args[1], kes.Identity(args[0])); err != nil {
		return fmt.Errorf("Failed to assign policy '%s' to '%s': %v", args[1], args[0], err)
	}
	return nil
}

const listIdentityCmdUsage = `usage: %s [<pattern>]

  -k, --insecure       Skip X.509 certificate validation during TLS handshake  

  -h, --help           Show list of command-line options
`

func listIdentity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), listIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) > 1 {
		cli.Usage()
		os.Exit(2)
	}
	pattern := "*"
	if len(args) == 1 {
		pattern = args[0]
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	identityRoles, err := client.ListIdentities(pattern)
	if err != nil {
		return fmt.Errorf("Cannot list identities: %v", err)
	}
	identities := make([]string, 0, len(identityRoles))
	for id := range identityRoles {
		identities = append(identities, id.String())
	}
	sort.Strings(identities)

	if isTerm(os.Stdout) {
		fmt.Println("{")
		for _, id := range identities {
			fmt.Printf("  %s => %s\n", id, identityRoles[kes.Identity(id)])
		}
		fmt.Println("}")
	} else {
		fmt.Print("{")
		for i, id := range identities {
			if i < len(identities)-1 {
				fmt.Printf(`"%s":"%s",`, id, identityRoles[kes.Identity(id)])
			} else {
				fmt.Printf(`"%s":"%s"`, id, identityRoles[kes.Identity(id)])
			}
		}
		fmt.Print("}")
	}
	return nil
}

const forgetIdentityCmdUsage = `usage: %s <identity>

  -k, --insecure       Skip X.509 certificate validation during TLS handshake  
  
  -h, --help           Show list of command-line options
`

func forgetIdentity(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), forgetIdentityCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 1 {
		cli.Usage()
		os.Exit(2)
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	if err := client.ForgetIdentity(kes.Identity(args[0])); err != nil {
		return fmt.Errorf("Cannot forget '%s': %v", args[0], err)
	}
	return nil
}
