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

	"github.com/minio/kes"
)

const policyCmdUsage = `Usage:
    kes policy <command>

Commands:
    add                    Add a new policy
    show                   Download and print a policy
    list                   List policies
    delete                 Delete a policy

Options:
    -h, --help             Show list of command-line options
`

func policy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, policyCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(1)
	}

	switch args := cli.Args(); args[0] {
	case "add":
		addPolicy(args)
	case "show":
		showPolicy(args)
	case "list":
		listPolicies(args)
	case "delete":
		deletePolicy(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes policy command. See 'kes policy --help'", args[0])
	}
}

const addPolicyCmdUsage = `Usage:
    kes policy add [options] <name> [<path>]

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Creates a new policy with the given <name> at the KES server.
The path must point to a KES policy json file. If the <path> is
omitted the policy file is read from standard input.

Examples:
    $ kes policy add my-policy ./policy.json
`

func addPolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, addPolicyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no policy name specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name  = cli.Arg(0)
		input = os.Stdin
	)
	if cli.NArg() == 2 && cli.Arg(1) != "-" {
		f, err := os.Open(cli.Arg(1))
		if err != nil {
			stdlog.Fatalf("Error: failed to open %q: %v", cli.Arg(1), err)
		}
		defer f.Close()
		input = f
	}

	var policy kes.Policy
	if err := json.NewDecoder(input).Decode(&policy); err != nil {
		if input == os.Stdin {
			stdlog.Fatalf("Error: failed to read policy file from standard input: %v", err)
		}
		stdlog.Fatalf("Error: failed to read policy file from %q: %v", input.Name(), err)
	}

	var (
		client         = newClient(insecureSkipVerify)
		ctx, cancelCtx = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	)
	defer cancelCtx()

	if err := client.SetPolicy(ctx, name, &policy); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to add policy %q: %v", name, err)
	}
}

const showPolicyCmdUsage = `Usage:
    kes policy show [options] <name>

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Downloads and displays the KES policy referenced by <name>.

Examples:
    $ kes policy show my-policy
`

func showPolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, showPolicyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no policy name specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name           = cli.Arg(0)
		client         = newClient(insecureSkipVerify)
		ctx, cancelCtx = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	)
	defer cancelCtx()

	policy, err := client.GetPolicy(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to fetch policy %q: %v", name, err)
	}

	output, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
	os.Stdout.Write(output)
	if isTerm(os.Stdout) {
		os.Stdout.WriteString("\n")
	}
}

const listPoliciesCmdUsage = `Usage:
    kes policy list [options] [<pattern>]

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Lists all policies at the KES server that match the given <pattern>.
If the <pattern> is omitted the default pattern '*' is used. This
pattern matches any policy name, and therefore, lists all policies.

Examples:
    $ kes policy list my-pol* 
`

func listPolicies(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, listPoliciesCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	var pattern = "*"
	if cli.NArg() == 1 {
		pattern = cli.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	policies, err := newClient(insecureSkipVerify).ListPolicies(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to list policies matching %q: %v", pattern, err)
	}
	sort.Strings(policies)
	if isTerm(os.Stdout) {
		fmt.Println("[")
		for _, p := range policies {
			fmt.Printf("  %s\n", p)
		}
		fmt.Println("]")
	} else {
		json.NewEncoder(os.Stdout).Encode(policies)
	}
}

const deletePolicyCmdUsage = `Usage:
    kes policy delete [options] <name>

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Deletes the policy referenced by <name>.

Examples:
    $ kes policy delete my-policy
`

func deletePolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, deletePolicyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no policy name specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name           = cli.Arg(0)
		ctx, cancelCtx = signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	)
	defer cancelCtx()

	if err := newClient(insecureSkipVerify).DeletePolicy(ctx, name); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to delete policy %q: %v", name, err)
	}
}
