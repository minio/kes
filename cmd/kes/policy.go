// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const policyCmdUsage = `Usage:
    kes policy <command>

Commands:
    create                   Create a new policy.
    assign                   Assign a policy to identities.
    ls                       List policies.
    rm                       Remove a policy.
    show                     Display a policy.

Options:
    -h, --help               Print command line options.
`

func policyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, policyCmdUsage) }

	subCmds := commands{
		"create": createPolicyCmd,
		"assign": assignPolicyCmd,
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
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes policy add my-policy ./policy.json
`

func createPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, createPolicyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy create --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no policy name specified. See 'kes policy create --help'")
	case cmd.NArg() == 1:
		cli.Fatal("no policy file specified. See 'kes policy create --help'")
	case cmd.NArg() > 2:
		cli.Fatal("too many arguments. See 'kes policy create --help'")
	}

	name := cmd.Arg(0)
	filename := cmd.Arg(1)
	b, err := os.ReadFile(filename)
	if err != nil {
		cli.Fatalf("failed to read %q: %v", filename, err)
	}

	var policy kes.Policy
	if err = json.Unmarshal(b, &policy); err != nil {
		cli.Fatalf("failed to read %q: %v", filename, err)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	client := newClient(insecureSkipVerify)
	if err := client.SetPolicy(ctx, name, &policy); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create policy %q: %v", name, err)
	}
}

const assignPolicyCmdUsage = `Usage:
    kes policy assign [options] <policy> <identity>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes policy assign my-policy 032dc24c353f1baf782660635ade933c601095ba462a44d1484a511c4271e212
`

func assignPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, assignPolicyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy assign --help'", err)
	}

	if cmd.NArg() == 0 {
		cli.Fatal("no policy name specified. See 'kes policy assign --help'")
	}
	if cmd.NArg() == 1 {
		cli.Fatal("no identity specified. See 'kes policy assign --help'")
	}

	policy := cmd.Arg(0)
	client := newClient(insecureSkipVerify)

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	for _, identity := range cmd.Args()[1:] { // cmd.Arg(0) is the policy
		if err := client.AssignPolicy(ctx, policy, kes.Identity(identity)); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to assign policy %q to %q: %v", policy, identity, err)
		}
	}
}

const lsPolicyCmdUsage = `Usage:
    kes policy ls [options] [<pattern>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes policy ls
    $ kes policy ls 'my-policy*'
`

func lsPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, lsPolicyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes policy ls --help'")
	}

	pattern := "*"
	if cmd.NArg() == 1 {
		pattern = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	client := newClient(insecureSkipVerify)
	policies, err := client.ListPolicies(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to list policies: %v", err)
	}
	defer policies.Close()

	if isTerm(os.Stdout) {
		for policies.Next() {
			fmt.Println(policies.Name())
		}
	} else {
		if _, err = policies.WriteTo(os.Stdout); err != nil {
			cli.Fatal(err)
		}
	}
	if err = policies.Close(); err != nil {
		cli.Fatalf("failed to list policies: %v", err)
	}
}

const rmPolicyCmdUsage = `Usage:
    kes policy rm [options] <name>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes policy delete my-policy
    $ kes policy delete my-policy1, my-policy2
`

func rmPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmPolicyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no policy name specified. See 'kes policy rm --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	client := newClient(insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := client.DeletePolicy(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to delete policy %q: %v", name, err)
		}
	}
}

const showPolicyCmdUsage = `Usage:
    kes policy show [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print policy in JSON format.
    -h, --help               Print command line options.

Examples:
    $ kes policy show my-policy
`

func showPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, showPolicyCmdUsage) }

	var (
		insecureSkipVerify bool
		jsonFlag           bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print policy in JSON format.")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy show --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no policy name specified. See 'kes policy show --help'")
	}

	name := cmd.Arg(0)
	client := newClient(insecureSkipVerify)

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	policy, err := client.GetPolicy(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to show policy '%s': %v", name, err)
	}
	if !isTerm(os.Stdout) || jsonFlag {
		type Response struct {
			Allow     []string     `json:"allow,omitempty"`
			Deny      []string     `json:"deny,omitempty"`
			CreatedAt time.Time    `json:"created_at,omitempty"`
			CreatedBy kes.Identity `json:"created_by,omitempty"`
		}
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		err = encoder.Encode(Response{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: policy.Info.CreatedAt,
			CreatedBy: policy.Info.CreatedBy,
		})
		if err != nil {
			cli.Fatalf("failed to show policy '%s': %v", name, err)
		}
	} else {
		const (
			Red   tui.Color = "#d70000"
			Green tui.Color = "#00a700"
			Cyan  tui.Color = "#00afaf"
		)
		if len(policy.Allow) > 0 {
			header := tui.NewStyle().Bold(true).Foreground(Green)
			fmt.Println(header.Render("Allow:"))
			for _, rule := range policy.Allow {
				fmt.Println("  · " + rule)
			}
		}
		if len(policy.Deny) > 0 {
			if len(policy.Allow) > 0 {
				fmt.Println()
			}
			header := tui.NewStyle().Bold(true).Foreground(Red)
			fmt.Println(header.Render("Deny:"))
			for _, rule := range policy.Deny {
				fmt.Println("  · " + rule)
			}
		}

		fmt.Println()
		header := tui.NewStyle().Bold(true).Foreground(Cyan)
		if !policy.Info.CreatedAt.IsZero() {
			year, month, day := policy.Info.CreatedAt.Local().Date()
			hour, min, sec := policy.Info.CreatedAt.Local().Clock()
			fmt.Printf("\n%s %04d-%02d-%02d %02d:%02d:%02d\n", header.Render("Created at:"), year, month, day, hour, min, sec)
		}
		if !policy.Info.CreatedBy.IsUnknown() {
			fmt.Println(header.Render("Created by:"), policy.Info.CreatedBy)
		} else {
			fmt.Println(header.Render("Created by:"), "<unknown>")
		}
	}
}
