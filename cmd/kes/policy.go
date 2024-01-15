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
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kms-go/kes"
	flag "github.com/spf13/pflag"
)

const policyCmdUsage = `Usage:
    kes policy <command>

Commands:
    info                     Get information about a policy.
    ls                       List policies.
    rm                       Remove a policy.
    show                     Display a policy.

Options:
    -h, --help               Print command line options.
`

func policyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, policyCmdUsage) }

	subCmds := commands{
		"info": infoPolicyCmd,
		"ls":   lsPolicyCmd,
		"show": showPolicyCmd,
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

const lsPolicyCmdUsage = `Usage:
    kes policy ls [options] [<pattern>]

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print policies in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.

    -h, --help               Print command line options.

Examples:
    $ kes policy ls
    $ kes policy ls 'my-policy*'
`

func lsPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsPolicyCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
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

	prefix := "*"
	if cmd.NArg() == 1 {
		prefix = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newClient(insecureSkipVerify)
	iter := &kes.ListIter[string]{
		NextFunc: enclave.ListPolicies,
	}

	var names []string
	for id, err := iter.SeekTo(ctx, prefix); err != io.EOF; id, err = iter.Next(ctx) {
		if err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}
		names = append(names, id)
	}

	if jsonFlag {
		if err := json.NewEncoder(os.Stdout).Encode(names); err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}
	}
	if len(names) == 0 {
		return
	}

	var (
		style = tui.NewStyle().Underline(colorFlag.Colorize())
		buf   = &strings.Builder{}
	)
	fmt.Fprintln(buf, style.Render("Key"))
	for _, name := range names {
		buf.WriteString(name)
		buf.WriteByte('\n')
	}
	fmt.Print(buf)
}

const infoPolicyCmdUsage = `Usage:
    kes policy info [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print policy in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes policy info my-policy
`

func infoPolicyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, infoPolicyCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print policy in JSON format.")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes policy show --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no policy name specified. See 'kes policy show --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	name := cmd.Arg(0)
	client := newClient(insecureSkipVerify)
	info, err := client.DescribePolicy(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if err = encoder.Encode(info); err != nil {
			cli.Fatal(err)
		}
	} else {
		var faint, policyStyle tui.Style
		if colorFlag.Colorize() {
			const ColorPolicy tui.Color = "#2e42d1"
			faint = faint.Faint(true)
			policyStyle = policyStyle.Foreground(ColorPolicy)
		}
		fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Name")), policyStyle.Render(name))
		if !info.CreatedAt.IsZero() {
			year, month, day := info.CreatedAt.Local().Date()
			hour, min, sec := info.CreatedAt.Local().Clock()
			fmt.Println(
				faint.Render(fmt.Sprintf("%-11s", "Date")),
				fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
			)
		}
		if !info.CreatedBy.IsUnknown() {
			fmt.Println(faint.Render(fmt.Sprintf("%-11s", "Created by")), info.CreatedBy)
		}
	}
}

const showPolicyCmdUsage = `Usage:
    kes policy show [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.
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
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print policy in JSON format.")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
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
			Allow     map[string]kes.Rule `json:"allow,omitempty"`
			Deny      map[string]kes.Rule `json:"deny,omitempty"`
			CreatedAt time.Time           `json:"created_at,omitempty"`
			CreatedBy kes.Identity        `json:"created_by,omitempty"`
		}
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		err = encoder.Encode(Response{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: policy.CreatedAt,
			CreatedBy: policy.CreatedBy,
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
			for rule := range policy.Allow {
				fmt.Println("  · " + rule)
			}
		}
		if len(policy.Deny) > 0 {
			if len(policy.Allow) > 0 {
				fmt.Println()
			}
			header := tui.NewStyle().Bold(true).Foreground(Red)
			fmt.Println(header.Render("Deny:"))
			for rule := range policy.Deny {
				fmt.Println("  · " + rule)
			}
		}

		fmt.Println()
		header := tui.NewStyle().Bold(true).Foreground(Cyan)
		if !policy.CreatedAt.IsZero() {
			year, month, day := policy.CreatedAt.Local().Date()
			hour, min, sec := policy.CreatedAt.Local().Clock()
			fmt.Printf("\n%s %04d-%02d-%02d %02d:%02d:%02d\n", header.Render("Created at:"), year, month, day, hour, min, sec)
		}
		if !policy.CreatedBy.IsUnknown() {
			fmt.Println(header.Render("Created by:"), policy.CreatedBy)
		} else {
			fmt.Println(header.Render("Created by:"), "<unknown>")
		}
	}
}
