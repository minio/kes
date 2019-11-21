package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	"github.com/aead/key"
)

const policyCmdUsage = `Manage named key policies.

usage: %s <command>
  
  add                  Add a named policy to the policy set.
  show                 Download and print a named policy.
  list                 List all named policies.
  delete               Delete a named policy.

  -h, --help           Show list of command-line options
`

func policy(args []string) {
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
		addPolicy(args)
	case "show":
		showPolicy(args)
	case "ls", "list":
		listPolicies(args)
	case "delete":
		deletePolicy(args)
	default:
		cli.Usage()
		os.Exit(2)
	}
}

const addPolicyCmdUsage = `Adds a named policy to the policy set of the key server.

It reads a TOML or JSON encoded policy from the specified file
and adds it to the policy set of the key server. The policy will
be available under the specified policy name.

usage: %s <policy> <file>
  
  --json               Encode policy as JSON instead of TOML. 

  -h, --help           Show list of command-line options
`

func addPolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), addPolicyCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) != 2 {
		cli.Usage()
		os.Exit(2)
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       loadClientCertificates(),
	})

	data, err := ioutil.ReadFile(args[1])
	if err != nil {
		failf(cli.Output(), "Cannot read policy file '%s': %v", args[1], err)
	}
	var policy key.Policy
	if err = policy.UnmarshalTOML(data); err != nil {
		if err = policy.UnmarshalJSON(data); err != nil {
			failf(cli.Output(), "Policy file contains neither valid TOML nor valid JSON")
		}
	}

	if err := client.WritePolicy(args[0], &policy); err != nil {
		failf(cli.Output(), "Failed to add policy '%s': %v", args[0], err)
	}
}

const showPolicyCmdUsage = `Downloads and prints key policies.

It prints the policy definition of a named policy to STDOUT.
By default, the policy definition is printed in a human-readable
format to a terminal or as TOML to a UNIX pipe / file.

usage: %s <policy>
  
  --json               Encode policy as JSON instead of TOML. 

  -h, --help           Show list of command-line options
`

func showPolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), showPolicyCmdUsage, cli.Name())
	}

	var formatJSON bool
	cli.BoolVar(&formatJSON, "json", false, "")

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
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

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       loadClientCertificates(),
	})

	policy, err := client.ReadPolicy(name)
	if err != nil {
		failf(cli.Output(), "Failed to fetch policy '%s': %v", args[0], err)
	}
	switch {
	case isTerm(os.Stdout) && !formatJSON:
		fmt.Println(policy.String())
	case formatJSON:
		output, _ := policy.MarshalJSON()
		os.Stdout.Write(output)
	default:
		output, _ := policy.MarshalTOML()
		os.Stdout.Write(output)
	}
}

const listPoliciesCmdUsage = `List all named policies.

It prints the name of each policy to STDOUT. By default,
the policy definition is printed in a human-readable
format to a terminal or as JSON to a UNIX pipe / file.
`

func listPolicies(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Print(cli.Output(), listPoliciesCmdUsage)
	}

	cli.Parse(args[1:])
	if cli.NArg() != 0 {
		cli.Usage()
		os.Exit(2)
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       loadClientCertificates(),
	})

	policies, err := client.ListPolicies()
	if err != nil {
		failf(cli.Output(), "Failed to list policies: %v", err)
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

const deletePolicyCmdUsage = `Deletes a named policy.

usage: %s <policy>

  -h, --help           Show list of command-line options
`

func deletePolicy(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), deletePolicyCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) != 1 {
		cli.Usage()
		os.Exit(2)
	}

	client := key.NewClient(serverAddr(), &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       loadClientCertificates(),
	})

	if err := client.DeletePolicy(args[0]); err != nil {
		failf(cli.Output(), "Failed to delete policy '%s': %v", args[0], err)
	}
}
