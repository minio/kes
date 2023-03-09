// Copyright 2022 - MinIO, Inc. All rights reserved.
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

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const enclaveCmdUsage = `Usage:
    kes enclave <command>

Commands:
    create                   Create a new enclave.
    info                     Get information about an enclave. 
    rm                       Delete an enclave.

Options:
    -h, --help               Print command line options.
`

func enclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, enclaveCmdUsage) }

	subCmds := commands{
		"create": createEnclaveCmd,
		"info":   describeEnclaveCmd,
		"rm":     deleteEnclaveCmd,
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
		cli.Fatalf("%v. See 'kes enclave --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatalf("%q is not a enclave command. See 'kes enclave --help'", cmd.Arg(0))
	}
	cmd.Usage()
	os.Exit(2)
}

const createEnclaveCmdUsage = `Usage:
    kes enclave create [options] <name> <identity>

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes enclave create tenant-1 5f2f4ef3e0e340a07fc330f58ef0a1c4d661e564ab10795f9231f75fcfe572f1
`

func createEnclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createEnclaveCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes enclave create --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no enclave name specified. See 'kes enclave create --help'")
	case cmd.NArg() == 1:
		cli.Fatal("no admin identity specified. See 'kes enclave create --help'")
	case cmd.NArg() > 2:
		cli.Fatal("too many arguments. See 'kes enclave create --help'")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	name := cmd.Arg(0)
	admin := cmd.Arg(1)
	client := newClient(insecureSkipVerify)
	if err := client.CreateEnclave(ctx, name, kes.Identity(admin)); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create enclave '%s': %v", name, err)
	}
}

const describeEnclaveCmdUsage = `Usage:
    kes enclave info [options] [<name>]

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print identity information in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.

    -h, --help               Print command line options.

Examples:
    $ kes enclave info tenant-1
`

func describeEnclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeEnclaveCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print policy information in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes enclave info --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes enclave info --help'")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	var name string
	if cmd.NArg() > 0 {
		name = cmd.Arg(0)
	}
	client := newClient(insecureSkipVerify)
	info, err := client.DescribeEnclave(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to describe enclave '%s': %v", name, err)
	}

	if jsonFlag {
		if err := json.NewEncoder(os.Stdout).Encode(info); err != nil {
			cli.Fatalf("failed to describe enclave '%s': %v", name, err)
		}
		return
	}

	var faint, enclaveStyle tui.Style
	if colorFlag.Colorize() {
		const ColorIdentity tui.Color = "#2e42d1"
		faint = faint.Faint(true).Bold(true)
		enclaveStyle = enclaveStyle.Foreground(ColorIdentity)
	}

	year, month, day := info.CreatedAt.Date()
	hour, min, sec := info.CreatedAt.Clock()
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Enclave")),
		enclaveStyle.Render(info.Name),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Created At")),
		fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Created By")),
		info.CreatedBy,
	)
}

const deleteEnclaveCmdUsage = `Usage:
    kes enclave rm [options] <name>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes enclave rm tenant-1
`

func deleteEnclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, deleteEnclaveCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes enclave delete --help'", err)
	}

	if cmd.NArg() == 0 {
		cli.Fatal("no enclave name specified. See 'kes enclave delete --help'")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	client := newClient(insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := client.DeleteEnclave(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to delete enclave '%s': %v", name, err)
		}
	}
}
