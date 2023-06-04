// Copyright 2022 - MinIO, Inc. All rights reserved.
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

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const enclaveCmdUsage = `Usage:
    kes enclave <command>

Commands:
    create                   Create a new enclave
    info                     Fetch enclave metadata
    ls                       List enclaves
    rm                       Delete an enclave

Options:
    -h, --help               Print command line options

Examples:
  1. Create a new enclave 'tenant-1'.
     $ kes enclave create tenant-1

  2. Fetch metadata information about the enclave 'tenant-1'.
     $ kes enclave info tenant-1
	
  3. List all enclave names.
     $ kes enclave ls

  4. Delete the enclave 'tenant-1'. 
     $ kes enclave rm 'tenant-1'
`

func enclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, enclaveCmdUsage) }

	subCmds := cli.SubCommands{
		"create": createEnclaveCmd,
		"info":   describeEnclaveCmd,
		"ls":     listEnclavesCmd,
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
    kes enclave create [options] <name>

Options:
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Create a new enclave named 'tenant-1'
     $ kes enclave create tenant-1
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
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes enclave create --help'")
	}

	name := cmd.Arg(0)
	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := client.CreateEnclave(ctx, name); err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create enclave '%s': %v", name, err)
	}
}

const describeEnclaveCmdUsage = `Usage:
    kes enclave info [options] [<name>]

Options:
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show metadata of the enclave $KES_ENCLAVE
     $ kes enclave info

  2. Show metadata of the enclave 'tenant-1'
     $ kes enclave info tenant-1
`

func describeEnclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeEnclaveCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes enclave info --help'", err)
	}

	enclave, ok := os.LookupEnv(cli.EnvEnclave)
	switch {
	case cmd.NArg() == 0 && !ok:
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no enclave name specified")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes enclave info --help'")
	}

	if cmd.NArg() > 0 {
		enclave = cmd.Arg(0)
	}
	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	info, err := client.DescribeEnclave(ctx, enclave)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to describe enclave '%s': %v", enclave, err)
	}

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(info); err != nil {
			cli.Fatalf("failed to describe enclave '%s': %v", enclave, err)
		}
		return
	}

	const ColorEnclave tui.Color = "#2283f3"
	enclaveStyle := tui.NewStyle().Foreground(ColorEnclave).Bold(true)

	year, month, day := info.CreatedAt.Date()
	hour, min, sec := info.CreatedAt.Clock()
	zone, _ := info.CreatedAt.Zone()

	buf := cli.Buffer{}
	buf.Stylef(enclaveStyle, "%-8s : %s", "Name", enclave).Sprintln()
	buf.Sprintf("%-8s : %04d-%02d-%02d %02d:%02d:%02d %s", "Date", year, month, day, hour, min, sec, zone).Sprintln()
	buf.Sprintf("%-8s : %v", "Owner", info.CreatedBy)
	cli.Println(buf.String())
}

const listEnclavesCmdUsage = `Usage:
    kes enclave ls [options] [<prefix>]

Options:
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. List all enclave names.
     $ kes enclave ls
	
  2. List enclave names starting with 'foo'.
     $ kes enclave ls foo
`

func listEnclavesCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, listEnclavesCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print listing information in JSON format")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip server certificate verification")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cmd.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		cli.Fatal(err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes enclave ls --help'")
	}

	prefix := ""
	if cmd.NArg() > 0 {
		prefix = cmd.Arg(0)
	}

	client := newClient(insecureSkipVerify)
	iter := kes.ListIter[string]{
		NextFunc: client.ListEnclaves,
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
			if prefix != "" {
				cli.Fatalf("failed to list enclaves at '%s': %v", prefix, err)
			}
			cli.Fatalf("failed to list enclaves: %v", err)
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
			cli.Fatalf("failed to list enclaves: %v", err)
		}
		return
	}

	if len(names) == 0 {
		return
	}
	var buf cli.Buffer
	if isTerm(os.Stdout) {
		buf.Styleln(tui.NewStyle().Underline(true).Bold(true), "Enclaves")
	}
	for _, name := range names {
		buf.Sprintln(name)
	}
	cli.Print(buf.String())
}

const deleteEnclaveCmdUsage = `Usage:
    kes enclave rm [options] <name>

Options:
    -f, --force              Skip confirmation dialog
    -k, --insecure           Skip server certificate verification
	
    -h, --help               Print command line options

Examples:
  1. Delete the enclave 'tenant-1'.
     $ kes enclave rm tenant-1

  2. Delete the enclave 'tenant-1' without confirmation.
     $ kes enclave rm --force tenant-1
`

func deleteEnclaveCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, deleteEnclaveCmdUsage) }

	var (
		insecureSkipVerify bool
		forceFlag          bool
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip server certificate verification")
	cmd.BoolVarP(&forceFlag, "force", "f", false, "Skip confirmation dialog")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cmd.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		cli.Fatal(err)
	}

	switch {
	case cmd.NArg() == 0:
		cmd.Usage()
		os.Exit(1)
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes enclave rm --help'")
	}

	name := cmd.Arg(0)
	if !forceFlag && isTerm(os.Stdin) {
		const Warn tui.Color = "#ffcc00"
		warnStyle := tui.NewStyle().Foreground(Warn)

		buf := cli.Buffer{}
		buf.Stylef(warnStyle, "Warning: ")
		buf.Sprintf("You are about to delete the enclave '%s'", name).Sprintln()
		buf.Sprintf("%-8s This will remove all data within '%s'.", " ", name).Sprintln()
		buf.Sprintln()
		buf.Sprint("Confirm deletion by entering the enclave name again: ")
		fmt.Fprint(os.Stderr, buf.String())

		confirm, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			cli.Fatal(err)
		}
		fmt.Fprintln(os.Stderr) // Add the newline again

		if name != string(confirm) {
			cli.Fatal("Aborted")
		}
	}

	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := client.DeleteEnclave(ctx, name); err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to delete enclave '%s': %v", name, err)
	}
}
