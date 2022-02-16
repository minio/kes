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

	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const keyCmdUsage = `Usage:
    kes key <command>

Commands:
    create                   Create a new crypto key.
    import                   Import a crypto key.
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
    -h, --help               Print command line options.

Examples:
    $ kes key create my-key
    $ kes key create my-key1 my-key2
`

func createKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := client.CreateKey(ctx, name); err != nil {
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
    -h, --help               Print command line options.

Examples:
    $ kes key import my-key-2 Xlnr/nOgAWE5cA7GAsl3L2goCvmfs6KE0gNgB1T93wE=
`

func importKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, importKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	if err = client.ImportKey(ctx, name, key); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to import %q: %v", name, err)
	}
}

const lsKeyCmdUsage = `Usage:
    kes key ls [options] [<pattern>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes key ls
    $ kes key ls 'my-key*'
`

func lsKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	iterator, err := client.ListKeys(ctx, pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to list keys: %v", err)
	}
	defer iterator.Close()

	if isTerm(os.Stdout) {
		for iterator.Next() {
			fmt.Println(iterator.Value().Name)
		}
	} else {
		encoder := json.NewEncoder(os.Stdout)
		for iterator.Next() {
			encoder.Encode(iterator.Value())
		}
	}
	if err = iterator.Close(); err != nil {
		cli.Fatal(err)
	}
}

const rmKeyCmdUsage = `Usage:
    kes key rm [options] <name>...

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake.
    -h, --help             Show list of command-line options.

Examples:
    $ kes key rm my-key
    $ kes key rm my-key1 my-key2
`

func rmKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	for _, name := range cmd.Args() {
		if err := client.DeleteKey(ctx, name); err != nil {
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
    -h, --help               Print command line options.

Examples:
    $ kes key encrypt my-key "Hello World"
`

func encryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, encryptKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	ciphertext, err := client.Encrypt(ctx, name, []byte(message), nil)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to encrypt message: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\n  ciphertext: %s\n", base64.StdEncoding.EncodeToString(ciphertext))
	} else {
		fmt.Printf(`{"ciphertext":"%s"}`, base64.StdEncoding.EncodeToString(ciphertext))
	}
}

const decryptKeyCmdUsage = `Usage:
    kes key decrypt [options] <name> <ciphertext> [<context>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ CIPHERTEXT=$(kes key dek my-key | jq -r .ciphertext)
    $ kes key decrypt my-key "$CIPHERTEXT"
`

func decryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, decryptKeyCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	plaintext, err := client.Decrypt(ctx, name, ciphertext, associatedData)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to decrypt ciphertext: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Printf("\n  plaintext: %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		fmt.Printf(`{"plaintext":"%s"}`, base64.StdEncoding.EncodeToString(plaintext))
	}
}

const dekCmdUsage = `Usage:
    kes key dek <name> [<context>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes key dek my-key
`

func dekCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, dekCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
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

	client := newClient(insecureSkipVerify)
	key, err := client.GenerateKey(ctx, name, associatedData)
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
		const format = "{\n  plaintext : %s\n  ciphertext: %s\n}\n"
		fmt.Printf(format, plaintext, ciphertext)
	} else {
		const format = `{"plaintext":"%x","ciphertext":"%x"}`
		fmt.Printf(format, plaintext, ciphertext)
	}
}
