// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"aead.dev/mem"
	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/secret"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const secretCmdUsage = `Usage:
    kes secret <command>

Commands:
    create                   Create a new secret.
    info                     Get information about a secret. 
    show                     Display a secret.
    ls                       List secrets.
    rm                       Delete a secret.

Options:
    -h, --help               Print command line options.
`

func secretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, secretCmdUsage) }

	subCmds := commands{
		"create": createSecretCmd,
		"info":   describeSecretCmd,
		"show":   showSecretCmd,
		"ls":     lsSecretCmd,
		"rm":     deleteSecretCmd,
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
		cli.Fatalf("%v. See 'kes key --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatalf("%q is not a key command. See 'kes key --help'", cmd.Arg(0))
	}
	cmd.Usage()
	os.Exit(2)
}

const createSecretCmdUsage = `Usage:
    kes secret create [options] <name> <value>

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.
        --file <name>        Use the file content as secret value.

    -h, --help               Print command line options.

Examples:
    $ kes secret create my-secret
      Enter secret:

    $ kes secret create my-secret password123
    $ kes secret create my-secret --file password.txt
`

func createSecretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createSecretCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
		filename           string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	cmd.StringVar(&filename, "file", "", "Use the file contet as secret value")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes secret create --help'", err)
	}

	switch n := cmd.NArg(); {
	case n == 0:
		cli.Fatal("no secret name specified. See 'kes secret create --help'")
	case n == 2 && filename != "":
		cli.Fatalf("cannot read from '%s' when a secret value is specified. See 'kes secret create --help'", filename)
	case n > 2:
		cli.Fatal("too many arguments. See 'kes secret create --help'")
	}

	var value []byte
	switch {
	case cmd.NArg() == 2:
		value = []byte(cmd.Arg(1))
	case filename != "":
		file, err := os.Open(filename)
		if err != nil {
			cli.Fatalf("failed to read '%s': %v", err)
		}
		defer file.Close()

		var buffer bytes.Buffer
		if _, err = io.Copy(&buffer, mem.LimitReader(os.Stdin, secret.MaxSize)); err != nil {
			cli.Fatalf("failed to read '%s': %v", err)
		}
		value = buffer.Bytes()
	default:
		fmt.Print("Enter secret: ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			cli.Fatalf("failed to read secret input: %v", err)
		}
		value = secret
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	name := cmd.Arg(0)
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	if err := enclave.CreateSecret(ctx, name, value, nil); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to create secret %q: %v", name, err)
	}
}

const describeSecretCmdUsage = `Usage:
    kes secret info [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print keys in JSON format. 
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes secret info my-secret
`

func describeSecretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeSecretCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes secret info --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no secret name specified. See 'kes secret info --help'")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes secret info --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	name := cmd.Arg(0)
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	info, err := enclave.DescribeSecret(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to describe keys: %v", err)
	}
	if jsonFlag {
		if err = json.NewEncoder(os.Stdout).Encode(info); err != nil {
			cli.Fatalf("failed to describe keys: %v", err)
		}
		return
	}

	var faint, nameStyle tui.Style
	if colorFlag.Colorize() {
		const ColorName tui.Color = "#2e42d1"
		faint = faint.Faint(true).Bold(true)
		nameStyle = nameStyle.Foreground(ColorName)
	}
	year, month, day := info.CreatedAt.Date()
	hour, min, sec := info.CreatedAt.Clock()

	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Name")),
		nameStyle.Render(info.Name),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Type")),
		info.Type.String(),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Created At")),
		fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
	)
	if info.CreatedBy.IsUnknown() {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created By")),
			"<unknown>",
		)
	} else {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created By")),
			info.CreatedBy,
		)
	}
}

const showSecretCmdUsage = `Usage:
    kes secret show [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation.
    -p, --plain              Print the raw secret without any styling.
        --json               Print the secret in JSON format. 
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes secret show my-secret
`

func showSecretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, showSecretCmdUsage) }

	var (
		plainFlag          bool
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.BoolVarP(&plainFlag, "plain", "p", false, "Print the raw secret without any styling")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes secret show --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no secret name specified. See 'kes secret show --help'")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes secret show --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	name := cmd.Arg(0)
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	secret, info, err := enclave.ReadSecret(ctx, name)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to describe keys: %v", err)
	}
	if plainFlag {
		fmt.Println(string(secret))
		return
	}
	if jsonFlag {
		type JSON struct {
			Bytes     []byte       `json:"bytes"`
			Name      string       `json:"name"`
			CreatedAt time.Time    `json:"created_at,omitempty"`
			CreatedBy kes.Identity `json:"created_by,omitempty"`
		}
		err = json.NewEncoder(os.Stdout).Encode(JSON{
			Bytes:     secret,
			Name:      info.Name,
			CreatedAt: info.CreatedAt,
			CreatedBy: info.CreatedBy,
		})
		if err != nil {
			cli.Fatalf("failed to describe keys: %v", err)
		}
		return
	}

	var faint, nameStyle tui.Style
	if colorFlag.Colorize() {
		const ColorName tui.Color = "#2e42d1"
		faint = faint.Faint(true).Bold(true)
		nameStyle = nameStyle.Foreground(ColorName)
	}
	year, month, day := info.CreatedAt.Date()
	hour, min, sec := info.CreatedAt.Clock()

	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Name")),
		nameStyle.Render(info.Name),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Type")),
		info.Type.String(),
	)
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Created At")),
		fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec),
	)
	if info.CreatedBy.IsUnknown() {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created By")),
			"<unknown>",
		)
	} else {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Created By")),
			info.CreatedBy,
		)
	}
	fmt.Println()
	fmt.Println(
		faint.Render(fmt.Sprintf("%-11s", "Value")),
		string(secret),
	)
}

const deleteSecretCmdUsage = `Usage:
    kes secret rm [options] <name>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes secret rm my-secret
`

func deleteSecretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, deleteSecretCmdUsage) }

	var (
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes secret rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no secret name specified. See 'kes secret rm --help'")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := enclave.DeleteSecret(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to remove secret %q: %v", name, err)
		}
	}
}

const lsSecretCmdUsage = `Usage:
    kes secret ls [options] [<pattern>]

Options:
    -k, --insecure           Skip TLS certificate validation.
        --json               Print keys in JSON format. 
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes secret ls
    $ kes secret ls 'my-secret*'
`

func lsSecretCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsSecretCmdUsage) }

	var (
		jsonFlag           bool
		colorFlag          colorOption
		insecureSkipVerify bool
		enclaveName        string
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print identities in JSON format")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Operate within the specified enclave")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes secret ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes secret ls --help'")
	}

	pattern := "*"
	if cmd.NArg() == 1 {
		pattern = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	iterator, err := enclave.ListSecrets(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to list secrets: %v", err)
	}
	defer iterator.Close()

	if jsonFlag {
		if _, err = iterator.WriteTo(os.Stdout); err != nil {
			cli.Fatal(err)
		}
		if err = iterator.Close(); err != nil {
			cli.Fatal(err)
		}
	} else {
		secrets, err := iterator.Values(0)
		if err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}
		if err = iterator.Close(); err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}

		if len(secrets) > 0 {
			sort.Slice(secrets, func(i, j int) bool {
				return strings.Compare(secrets[i].Name, secrets[j].Name) < 0
			})

			headerStyle := tui.NewStyle()
			dateStyle := tui.NewStyle()
			if colorFlag.Colorize() {
				const ColorDate tui.Color = "#5f8700"
				headerStyle = headerStyle.Underline(true).Bold(true)
				dateStyle = dateStyle.Foreground(ColorDate)
			}

			fmt.Println(
				headerStyle.Render(fmt.Sprintf("%-19s", "Date Created")),
				headerStyle.Render("Key"),
			)
			for _, key := range secrets {
				var date string
				if key.CreatedAt.IsZero() {
					date = fmt.Sprintf("%5s%s%5s", " ", "<unknown>", " ")
				} else {
					year, month, day := key.CreatedAt.Local().Date()
					hour, min, sec := key.CreatedAt.Local().Clock()
					date = fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec)
				}
				fmt.Printf("%s %s\n", dateStyle.Render(date), key.Name)
			}
		}

	}
}
