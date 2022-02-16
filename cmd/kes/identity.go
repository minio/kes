// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"sort"
	"strings"

	"github.com/minio/kes"
)

const identityCmdUsage = `Usage:
    kes identity <command>

    assign                 Assign an identity to a policy.
    list                   List identities at the KES server.
    forget                 Forget an identity.

Options:
    -h, --help             Show list of command-line options
`

func identity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, identityCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(1)
	}

	switch args := cli.Args(); args[0] {
	case "assign":
		assignIdentity(args)
	case "list":
		listIdentity(args)
	case "forget":
		forgetIdentity(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes identity command. See 'kes identity --help'", args[0])
	}
}

const assignIdentityCmdUsage = `Usage:
    kes identity assign [options] <identity> <policy>

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Assigns policies to identities. An identity is the cryptographic hash of
the public key that is part of the client TLS certificate. An identity
can be computed using:
    $ kes tool identity of <certificate>

Examples:
    $ MY_APP_IDENTITY=$(kes tool identity of my-app.crt)
    $ kes identity assign "$MY_APP_IDENTITY" my-app-policy
`

func assignIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, assignIdentityCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no identity specified")
	}
	if cli.NArg() == 1 {
		stdlog.Fatal("Error: no policy specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		client         = newClient(insecureSkipVerify)
		identity       = kes.Identity(cli.Arg(0))
		policy         = cli.Arg(1)
		ctx, cancelCtx = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	)
	defer cancelCtx()

	if err := client.AssignPolicy(ctx, policy, identity); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to assign identity %q to policy %q: %v", identity, policy, err)
	}
}

const listIdentityCmdUsage = `Usage:
    kes identity list [options] [<pattern>]

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Lists all identities that match the optional glob <pattern>. If the pattern
is omitted the pattern '*' is used by default. This pattern matches any identity,
and therefore, lists all identities.

Examples:
    $ kes identity list "3ecf*"
`

func listIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, listIdentityCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}

	pattern := "*"
	if cli.NArg() == 1 {
		pattern = cli.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	identities, err := newClient(insecureSkipVerify).ListIdentities(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to list identities matching %q: %v", pattern, err)
	}
	defer identities.Close()

	if isTerm(os.Stdout) {
		sortedIdentities := make([]kes.IdentityInfo, 0, 100)
		for identities.Next() {
			sortedIdentities = append(sortedIdentities, identities.Value())
		}
		if err = identities.Close(); err != nil {
			stdlog.Fatalf("Error: failed to list identities matching %q: %v", pattern, err)
		}
		sort.Slice(sortedIdentities, func(i, j int) bool {
			return strings.Compare(sortedIdentities[i].Identity.String(), sortedIdentities[j].Identity.String()) < 0
		})

		for _, id := range sortedIdentities {
			fmt.Printf("%s => %s\n", id.Identity, id.Policy)
		}
	} else {
		encoder := json.NewEncoder(os.Stdout)
		for identities.Next() {
			encoder.Encode(identities.Value())
		}
		if err = identities.Close(); err != nil {
			stdlog.Fatalf("Error: failed to list identities matching %q: %v", pattern, err)
		}
	}
}

const forgetIdentityCmdUsage = `Usage:
    kes identity forget <identity>

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Forgets an identity by removing the association between an identity and a policy.
An identity without a policy can not perform any action anymore. Therefore, forget
disables access for the given <identity>.

Examples:
    $ MY_APP_IDENTITY=$(kes tool identity of my-app.crt)
    $ kes identity forget "$MY_APP_IDENTITY"
`

func forgetIdentity(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, forgetIdentityCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no identity specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		client         = newClient(insecureSkipVerify)
		identity       = kes.Identity(cli.Arg(0))
		ctx, cancelCtx = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	)
	defer cancelCtx()

	if err := client.DeleteIdentity(ctx, identity); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to forget identity %q: %v", identity, err)
	}
}
