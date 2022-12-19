// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const keyCmdUsage = `Usage:
    kes key <command>

Commands:
    create                   Create a new crypto key.
    import                   Import a crypto key.
    info                     Get information about a crypto key. 
    ls                       List crypto keys.
    rm                       Delete a crypto key.

    encrypt                  Encrypt a message.
    decrypt                  Decrypt an encrypted message.
    dek                      Generate a new data encryption key.

Options:
    -h, --help               Print command line options.
`

func keyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, keyCmdUsage) }

	subCmds := commands{
		"create": createKeyCmd,
		"import": importKeyCmd,
		"info":   describeKeyCmd,
		"ls":     lsKeyCmd,
		"rm":     rmKeyCmd,

		"encrypt": encryptKeyCmd,
		"decrypt": decryptKeyCmd,
		"dek":     dekCmd,
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

const createKeyCmdUsage = `Usage:
    kes key create [options] <name>...

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes key create my-key
    $ kes key create my-key1 my-key2
`

func createKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key create --help'", err)
	}

	if cmd.NArg() == 0 {
		cli.Fatal("no key name specified. See 'kes key create --help'")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := enclave.CreateKey(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to create key %q: %v", name, err)
		}
	}
}

const importKeyCmdUsage = `Usage:
    kes key import [options] <name> [<key>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes key import my-key-2 Xlnr/nOgAWE5cA7GAsl3L2goCvmfs6KE0gNgB1T93wE=
`

func importKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, importKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key import --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no key name specified. See 'kes key import --help'")
	case cmd.NArg() == 1:
		cli.Fatal("no crypto key specified. See 'kes key import --help'")
	case cmd.NArg() > 2:
		cli.Fatal("too many arguments. See 'kes key import --help'")
	}
	name := cmd.Arg(0)
	key, err := base64.StdEncoding.DecodeString(cmd.Arg(1))
	if err != nil {
		cli.Fatalf("invalid key: %v. See 'kes key import --help'", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	if err = enclave.ImportKey(ctx, name, key); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to import %q: %v", name, err)
	}
}

const describeKeyCmdUsage = `Usage:
    kes key info [options] <name>

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
    $ kes key info my-key
`

func describeKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key info --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no key name specified. See 'kes key info --help'")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes key ls --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	name := cmd.Arg(0)
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	info, err := enclave.DescribeKey(ctx, name)
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
	if info.ID != "" {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "ID")),
			info.ID,
		)
	}
	if info.Algorithm != kes.KeyAlgorithmUndefined {
		fmt.Println(
			faint.Render(fmt.Sprintf("%-11s", "Algorithm")),
			info.Algorithm,
		)
	}
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

const lsKeyCmdUsage = `Usage:
    kes key ls [options] [<pattern>]

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
    $ kes key ls
    $ kes key ls 'my-key*'
`

func lsKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes key ls --help'")
	}

	pattern := "*"
	if cmd.NArg() == 1 {
		pattern = cmd.Arg(0)
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	iterator, err := enclave.ListKeys(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to list keys: %v", err)
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
		keys, err := iterator.Values(0)
		if err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}
		if err = iterator.Close(); err != nil {
			cli.Fatalf("failed to list keys: %v", err)
		}

		if len(keys) > 0 {
			sort.Slice(keys, func(i, j int) bool {
				return strings.Compare(keys[i].Name, keys[j].Name) < 0
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
			for _, key := range keys {
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

const rmKeyCmdUsage = `Usage:
    kes key rm [options] <name>...

Options:
    -k, --insecure           Skip X.509 certificate validation during TLS handshake.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Show list of command-line options.

Examples:
    $ kes key rm my-key
    $ kes key rm my-key1 my-key2
`

func rmKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cli.Fatal("no key name specified. See 'kes key rm --help'")
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := enclave.DeleteKey(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to remove key %q: %v", name, err)
		}
	}
}

const encryptKeyCmdUsage = `Usage:
    kes key encrypt [options] <name> <message>

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes key encrypt my-key "Hello World"
`

func encryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, encryptKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key encrypt --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no key name specified. See 'kes key encrypt --help'")
	case cmd.NArg() == 1:
		cli.Fatal("no message specified. See 'kes key encrypt --help'")
	case cmd.NArg() > 2:
		cli.Fatal("too many arguments. See 'kes key encrypt --help'")
	}

	name := cmd.Arg(0)
	message := cmd.Arg(1)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ciphertext, err := enclave.Encrypt(ctx, name, []byte(message), nil)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to encrypt message: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\nciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	} else {
		fmt.Printf(`{"ciphertext":"%s"}`, base64.StdEncoding.EncodeToString(ciphertext))
	}
}

const decryptKeyCmdUsage = `Usage:
    kes key decrypt [options] <name> <ciphertext> [<context>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ CIPHERTEXT=$(kes key dek my-key | jq -r .ciphertext)
    $ kes key decrypt my-key "$CIPHERTEXT"
`

func decryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, decryptKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key decrypt --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no key name specified. See 'kes key decrypt --help'")
	case cmd.NArg() == 1:
		cli.Fatal("no ciphertext specified. See 'kes key decrypt --help'")
	case cmd.NArg() > 3:
		cli.Fatal("too many arguments. See 'kes key decrypt --help'")
	}

	name := cmd.Arg(0)
	ciphertext, err := base64.StdEncoding.DecodeString(cmd.Arg(1))
	if err != nil {
		cli.Fatalf("invalid ciphertext: %v. See 'kes key decrypt --help'", err)
	}

	var associatedData []byte
	if cmd.NArg() == 3 {
		associatedData, err = base64.StdEncoding.DecodeString(cmd.Arg(2))
		if err != nil {
			cli.Fatalf("invalid context: %v. See 'kes key decrypt --help'", err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	plaintext, err := enclave.Decrypt(ctx, name, ciphertext, associatedData)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to decrypt ciphertext: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\nplaintext: %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		fmt.Printf(`{"plaintext":"%s"}`, base64.StdEncoding.EncodeToString(plaintext))
	}
}

const dekCmdUsage = `Usage:
    kes key dek <name> [<context>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -e, --enclave <name>     Operate within the specified enclave.

    -h, --help               Print command line options.

Examples:
    $ kes key dek my-key
`

func dekCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, dekCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key dek --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cli.Fatal("no key name specified. See 'kes key dek --help'")
	case cmd.NArg() > 2:
		cli.Fatal("too many arguments. See 'kes key dek --help'")
	}

	var associatedData []byte
	name := cmd.Arg(0)
	if cmd.NArg() == 2 {
		b, err := base64.StdEncoding.DecodeString(cmd.Arg(1))
		if err != nil {
			cli.Fatalf("invalid context: %v. See 'kes key dek --help'", err)
		}
		associatedData = b
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	key, err := enclave.GenerateKey(ctx, name, associatedData)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to derive key: %v", err)
	}

	var (
		plaintext  = base64.StdEncoding.EncodeToString(key.Plaintext)
		ciphertext = base64.StdEncoding.EncodeToString(key.Ciphertext)
	)
	if isTerm(os.Stdout) {
		const format = "\nplaintext:  %s\nciphertext: %s\n"
		fmt.Printf(format, plaintext, ciphertext)
	} else {
		const format = `{"plaintext":"%s","ciphertext":"%s"}`
		fmt.Printf(format, plaintext, ciphertext)
	}
}
