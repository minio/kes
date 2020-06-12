// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/minio/kes"
)

const policyCmdUsage = `Manage named KES policies.

usage: %s <command>
  
  add                  Add a new named policy.
  show                 Download and print a named policy.
  list                 List named policies.
  delete               Delete a named policy.

  -h, --help           Show list of command-line options
`

func policy(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), policyCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		return addPolicy(args)
	case "show":
		return showPolicy(args)
	case "list":
		return listPolicies(args)
	case "delete":
		return deletePolicy(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}

const addPolicyCmdUsage = `Adds a named policy to the policy set of the KES server.

It reads a JSON encoded policy from the specified file and
adds it to the policy set of the KES server.

usage: %s <policy> <file>
  
  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func addPolicy(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), addPolicyCmdUsage, cli.Name())
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
	data, err := ioutil.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("Cannot read policy file '%s': %v", args[1], err)
	}

	var policy kes.Policy
	if err = policy.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("Policy file is invalid JSON: %v", err)
	}
	if err = client.SetPolicy(args[0], &policy); err != nil {
		return fmt.Errorf("Failed to add policy '%s': %v", args[0], err)
	}
	return nil
}

const showPolicyCmdUsage = `Downloads and prints KES policies.

It prints the policy definition of a named policy to STDOUT.
By default, the policy definition is printed in a human-readable
format to a terminal or as JSON to a UNIX pipe / file.

usage: %s <policy>
   
  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func showPolicy(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), showPolicyCmdUsage, cli.Name())
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")

	if args = parseCommandFlags(cli, args[1:]); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	name := args[0]
	if len(args) > 1 {
		cli.Parse(args[1:])
		if cli.NArg() > 0 || cli.NFlag() != 1 {
			cli.Usage()
			os.Exit(2)
		}
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	policy, err := client.GetPolicy(name)
	if err != nil {
		return fmt.Errorf("Failed to fetch policy '%s': %v", args[0], err)
	}
	if isTerm(os.Stdout) {
		fmt.Println(policy.String())
	} else {
		output, _ := policy.MarshalJSON()
		os.Stdout.Write(output)
	}
	return nil
}

const listPoliciesCmdUsage = `List named policies.

It prints the name of each policy that matches the pattern
to STDOUT. If no pattern is specified the default pattern
which matches any policy name is used. By default, the
policy definition is printed in a human-readable format
to a terminal or as JSON to a UNIX pipe / file.

usage: %s [<pattern>]

  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func listPolicies(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Print(cli.Output(), listPoliciesCmdUsage)
	}

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) > 1 {
		cli.Usage()
		os.Exit(2)
	}
	var policy string
	if len(args) == 1 {
		policy = args[0]
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	policies, err := client.ListPolicies(policy)
	if err != nil {
		return fmt.Errorf("Failed to list policies: %v", err)
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
	return nil
}

const deletePolicyCmdUsage = `Deletes a named policy.

usage: %s <policy>

  -k, --insecure       Skip X.509 certificate validation during TLS handshake

  -h, --help           Show list of command-line options
`

func deletePolicy(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), deletePolicyCmdUsage, cli.Name())
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
	if err := client.DeletePolicy(args[0]); err != nil {
		return fmt.Errorf("Failed to delete policy '%s': %v", args[0], err)
	}
	return nil
}
