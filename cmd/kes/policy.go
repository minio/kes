// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
	"golang.org/x/exp/maps"
)

const policyCmdUsage = `Usage:
    kes policy <command>

Commands:
    create                   Create a new policy
    assign                   Assign a policy to identities
    show                     Display a policy
    info                     Get information about a policy
    ls                       List policies
    rm                       Delete a policy

Options:
    -h, --help               Print command line options
	
Examples:
  1. Create a policy named 'minio' from the file '~/minio-policy.json' within the enclave $KES_ENCLAVE.
     $ kes policy create minio ~/minio-policy.json

  2. Display the 'minio' policy within the enclave $KES_ENCLAVE.
     $ kes policy show minio

  3. Assign the 'minio' policy to the identity '204c7197416c440810231e793e0d74bf218d968780f65de6947c060524b48184'
     $ kes policy assign minio 204c7197416c440810231e793e0d74bf218d968780f65de6947c060524b48184

  4. Delete the 'minio' polciy within the enclave $KES_ENCLAVE.
     $ kes policy rm minio
`

func policyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, policyCmdUsage) }

	subCmds := cli.SubCommands{
		"create": createPolicyCmd,
		"assign": assignPolicyCmd,
		"info":   describePolicyCmd,
		"ls":     lsPolicyCmd,
		"rm":     rmPolicyCmd,
		"show":   showPolicyCmd,
	}
	if len(args) < 2 {
		cmd.Usage()
		os.Exit(2)
	}
	if cmd, ok := subCmds[args[1]]; ok {
		cmd(args[1:])
		return
	}
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatalf("%q is not a policy command. See 'kes policy --help'", cmd.Arg(0))
	}
	cmd.Usage()
	os.Exit(2)
}

const createPolicyCmdUsage = `Usage:
    kes policy create [options] <name> <path>

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Create a policy named 'minio' from the file './minio-policy.json' within the enclave $KES_ENCLAVE.
     $ kes policy create minio ./minio-policy.json

  2. Create a policy named 'my-policy' from the file './my-policy.json' within the enclave 'tenant-1'.
     $ cat my-policy.json | kes policy create my-policy
`

func createPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createPolicyCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy create --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}
	if cmd.NArg() == 1 && isTerm(os.Stdin) {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy file specified")
	}
	if cmd.NArg() > 2 {
		cli.Fatal("too many arguments. See 'kes policy create --help'")
	}

	in := os.Stdin
	if cmd.NArg() == 2 {
		f, err := os.Open(cmd.Arg(1))
		if err != nil {
			cli.Fatalf("failed to read policy: %v", err)
		}
		defer f.Close()
		in = f
	}

	var policy kes.Policy
	if err := json.NewDecoder(in).Decode(&policy); err != nil {
		cli.Fatalf("failed to read policy: %v", err)
	}
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := enclave.CreatePolicy(ctx, cmd.Arg(0), &policy); err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create policy '%s': %v", cmd.Arg(0), err)
	}
}

const assignPolicyCmdUsage = `Usage:
    kes policy assign [options] <policy> <identity>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Assign the 'minio' policy to the identity within the enclave $KES_ENCLAVE.
     $ kes policy assign minio 032dc24c353f1baf782660635ade933c601095ba462a44d1484a511c4271e212

  2. Assign the 'my-policy' policy to two identities within the enclave 'tenant-1'.
     $ kes policy assign --enclave tenant-1 my-policy 204c7197416c440810231e793e0d74bf218d968780f65de6947c060524b48184 \
           28cc38fd47d74747a4dab7f4dd04504730994c28f8a0f35933fcba4f87f5d218	
`

func assignPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, assignPolicyCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy assign --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}
	if cmd.NArg() == 1 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no identity specified")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()
	enclave := newEnclave(enclaveName, insecureSkipVerify)

	for _, identity := range cmd.Args()[1:] { // cmd.Arg(0) is the policy
		if err := enclave.AssignPolicy(ctx, cmd.Arg(0), kes.Identity(identity)); err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to assign policy '%s' to identity '%s': %v", cmd.Arg(0), identity, err)
		}
	}
}

const lsPolicyCmdUsage = `Usage:
    kes policy ls [options] [<prefix>]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. List all policy names within the enclave $KES_ENCLAVE.
     $ kes policy ls
	
  2. List all policy names starting with 'foo' within the enclave 'tenant-1'.
    $ kes policy ls --enclave tenant-1 foo
`

func lsPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsPolicyCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes policy ls --help'")
	}

	var prefix string
	if cmd.NArg() == 1 {
		prefix = cmd.Arg(0)
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	iter := kes.ListIter[string]{
		NextFunc: enclave.ListPolicies,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	var names []string
	for name, err := iter.SeekTo(ctx, prefix); err != io.EOF; name, err = iter.Next(ctx) {
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to list policies: %v", err)
		}
		names = append(names, name)
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(names); err != nil {
			cli.Fatalf("failed to list policies: %v", err)
		}
		return
	}

	if len(names) == 0 {
		return
	}
	var buf cli.Buffer
	if isTerm(os.Stdout) {
		buf.Styleln(tui.NewStyle().Underline(true).Bold(true), "Policies")
	}
	for _, name := range names {
		buf.Sprintln(name)
	}
	cli.Print(buf.String())
}

const rmPolicyCmdUsage = `Usage:
    kes policy rm [options] <name>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Delete the 'minio' policy within the enclave $KES_ENCLAVE.
     $ kes policy rm minio

  2. Delete the policies 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes policy rm --enclave tenant-1 foo bar
`

func rmPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmPolicyCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if err := enclave.DeletePolicy(ctx, name); err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to delete policy '%s': %v", name, err)
		}
	}
}

const describePolicyCmdUsage = `Usage:
    kes policy info [options] <name>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show metadata of the 'minio' policy within the enclave $KES_ENCLAVE.
     $ kes policy info minio

  1. Show metadata of the policies 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes policy info --enclave tenant-1 foo bar
`

func describePolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describePolicyCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy show --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}

	infos := map[string]*kes.PolicyInfo{}
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if _, ok := infos[name]; ok {
			continue // Avoid fetching a key info twice
		}

		info, err := enclave.DescribePolicy(ctx, name)
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to fetch metadata for policy '%s': %v", name, err)
		}
		infos[name] = info
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if len(infos) == 1 {
			for name, info := range infos {
				if err := encoder.Encode(info); err != nil {
					cli.Fatalf("failed to show policy metadata: %v", name, err)
				}
			}
			return
		}
		if err := encoder.Encode(infos); err != nil {
			cli.Fatalf("failed to show policy metadata: %v", err)
		}
		return
	}

	const ColorName tui.Color = "#2283f3"
	nameColor := tui.NewStyle().Foreground(ColorName)

	var buf cli.Buffer
	for i, name := range cmd.Args() {
		info, ok := infos[name]
		if !ok {
			continue
		}

		year, month, day := info.CreatedAt.Date()
		hour, min, sec := info.CreatedAt.Clock()
		zone, _ := info.CreatedAt.Zone()

		buf.Stylef(nameColor, "Name      : %s", info.Name).Sprintln()
		buf.Sprintf("Date      : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		buf.Sprintln("Owner     :", info.CreatedBy)
		if i < len(cmd.Args())-1 {
			buf.Sprintln()
		}
	}
	cli.Print(buf.String())
}

const showPolicyCmdUsage = `Usage:
    kes policy show [options] <name>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show the 'minio' policy within the enclave $KES_ENCLAVE.
     $ kes policy show minio

  1. Show the policies 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes policy show --enclave tenant-1 foo bar
`

func showPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, showPolicyCmdUsage) }

	var (
		insecureSkipVerify bool
		jsonFlag           bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy show --help'", err)
	}
	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no policy name specified")
	}

	policies := map[string]*kes.Policy{}
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if _, ok := policies[name]; ok {
			continue // Avoid fetching a policy twice
		}

		policy, err := enclave.GetPolicy(ctx, name)
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to fetch policy '%s': %v", name, err)
		}
		policies[name] = policy
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if len(policies) == 1 {
			for name, policy := range policies {
				if err := encoder.Encode(policy); err != nil {
					cli.Fatalf("failed to show policy '%s': %v", name, err)
				}
			}
			return
		}
		if err := encoder.Encode(policies); err != nil {
			cli.Fatalf("failed to show policies: %v", err)
		}
		return
	}

	const (
		ColorName tui.Color = "#2283f3"
	)
	nameColor := tui.NewStyle().Foreground(ColorName)

	var buf cli.Buffer
	for i, name := range cmd.Args() {
		policy, ok := policies[name]
		if !ok {
			continue
		}

		buf.Stylef(nameColor, "Name  : %s", name).Sprintln()
		if allow := maps.Keys(policy.Allow); len(allow) > 0 {
			sort.Strings(allow)
			buf.Sprintln("Allow {")
			for _, pattern := range allow {
				buf.Sprintf("        \"%s\",", pattern).Sprintln()
			}
			buf.Sprintln("}")
		}
		if deny := maps.Keys(policy.Deny); len(deny) > 0 {
			sort.Strings(deny)
			buf.Sprintln("Deny  {")
			for _, pattern := range deny {
				buf.Sprintf("        \"%s\",", pattern).Sprintln()
			}
			buf.Sprintln("}")
		}
		if i < len(cmd.Args())-1 {
			buf.Sprintln()
		}
	}
	cli.Print(buf.String())
}
