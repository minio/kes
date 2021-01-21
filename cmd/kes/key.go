// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"os"
)

const keyCmdUsage = `Usage:
    kes key <command>

Commands:
    create                  Create a new secret key at a KES server.
    delete                  Delete a secret key from a KES server.
	list                    List secret key names at a KES server.
    derive                  Derive a new key from a secret key.
    decrypt                 Decrypt a ciphertext with secret key.

Options:
   -h, --help               Show this list of command line options.
`

func key(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, keyCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args = cli.Args(); args[0] {
	case "create":
		createKey(args)
	case "list":
		listKeys(args)
	case "delete":
		deleteKey(args)
	case "derive":
		deriveKey(args)
	case "decrypt":
		decryptKey(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes key command. See 'kes key --help'", args[0])
	}
}

const createKeyCmdUsage = `Usage:
    kes key create [options] <name> [<key>]

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Creates a new key with the given <name> at the KES server. The optional key
must be a base64-encoded value. If no key is specified the KES server will
generate a new one at random.

Examples:
    $ kes key create my-key
    $ kes key create my-key-2 Xlnr/nOgAWE5cA7GAsl3L2goCvmfs6KE0gNgB1T93wE=
`

func createKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stdout, createKeyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no key name specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name  string = cli.Arg(0)
		bytes []byte
	)
	if cli.NArg() == 2 {
		b, err := base64.StdEncoding.DecodeString(cli.Arg(1))
		if err != nil {
			stdlog.Fatalf("Error: invalid key: %v", err)
		}
		bytes = b
	}

	var (
		client = newClient(insecureSkipVerify)
		ctx    = cancelOnSignal(os.Interrupt, os.Kill)
	)
	if len(bytes) > 0 {
		if err := client.ImportKey(ctx, name, bytes); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			stdlog.Fatalf("Error: failed to import key %q: %v", name, err)
		}
	} else {
		if err := client.CreateKey(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			stdlog.Fatalf("Failed to create key %q: %v", name, err)
		}
	}
}

const decryptKeyCmdUsage = `Usage:
    kes key decrypt [options] <name> <ciphertext> [<context>]

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Decrypts the <ciphertext> with the key referenced by <name> using an
optional <context> value that has been associated with the ciphertext.

The <ciphertext> as well as the <context> must be base64-encoded values.

Examples:
    $ CIPHERTEXT=$(kes key derive my-key | jq -r .ciphertext)
    $ kes key decrypt my-key "$CIPHERTEXT"
`

func decryptKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(cli.Output(), decryptKeyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no key name specified")
	}
	if cli.NArg() == 1 {
		stdlog.Fatal("Error: no ciphertext specified")
	}
	if cli.NArg() > 3 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name       string = cli.Arg(0)
		ciphertext []byte
		cryptoCtx  []byte
		err        error
	)
	ciphertext, err = base64.StdEncoding.DecodeString(cli.Arg(1))
	if err != nil {
		stdlog.Fatalf("Error: invalid ciphertext: %v", err)
	}
	if len(args) == 3 {
		cryptoCtx, err = base64.StdEncoding.DecodeString(cli.Arg(2))
		if err != nil {
			stdlog.Fatalf("Error: invalid context: %v", err)
		}
	}

	plaintext, err := newClient(insecureSkipVerify).Decrypt(cancelOnSignal(os.Interrupt, os.Kill), name, ciphertext, cryptoCtx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to decrypt ciphertext: %v", err)
	}
	if isTerm(os.Stdout) {
		fmt.Printf("\n  plaintext: %s\n", base64.StdEncoding.EncodeToString(plaintext))
	} else {
		fmt.Printf(`{"plaintext":"%s"}`, base64.StdEncoding.EncodeToString(plaintext))
	}
}

const deriveKeyCmdUsage = `Usage:
    kes key derive <name> [<context>]

Options:
   -k, --insecure         Skip X.509 certificate validation during TLS handshake
   -h, --help             Show list of command-line options

Derives a new cryptographic key from the master key <name> and returns the
plaintext as well the ciphertext of the key. The ciphertext can be decrypted
using:
    $ kes key decrypt <name> <ciphertext>

An optional context value can be associated with the returned ciphertext.
The <context> must be base64-encoded.

Examples:
    $ kes key derive my-key
`

func deriveKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, deriveKeyCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no key name specified")
	}
	if cli.NArg() > 2 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		name      string = cli.Arg(0)
		cryptoCtx []byte
	)
	if cli.NArg() == 2 {
		b, err := base64.StdEncoding.DecodeString(cli.Arg(1))
		if err != nil {
			stdlog.Fatalf("Error: invalid context: %v", err)
		}
		cryptoCtx = b
	}

	key, err := newClient(insecureSkipVerify).GenerateKey(cancelOnSignal(os.Interrupt, os.Kill), name, cryptoCtx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to derive key: %v", err)
	}

	if isTerm(os.Stdout) {
		fmt.Println("{")
		fmt.Printf("  plaintext : %s\n", base64.StdEncoding.EncodeToString(key.Plaintext))
		fmt.Printf("  ciphertext: %s\n", base64.StdEncoding.EncodeToString(key.Ciphertext))
		fmt.Println("}")
	} else {
		const format = `{"plaintext":"%s","ciphertext":"%s"}`
		fmt.Printf(format, base64.StdEncoding.EncodeToString(key.Plaintext), base64.StdEncoding.EncodeToString(key.Ciphertext))
	}
}

const listKeyCmdUsage = `Usage:
    kes key list [options] [<pattern>]

Options:
    --json                 Print key names as JSON
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Lists the description for all keys that match the optional <pattern>. If no
pattern is provided the default pattern ('*') is used - which matches any
key name, and therefore, lists all keys.

Examples:
    $ kes key list my-key*
`

func listKeys(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, listKeyCmdUsage) }

	var (
		insecureSkipVerify bool
		jsonFlag           bool
	)
	cli.BoolVar(&jsonFlag, "json", false, "Print key names as JSON")
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}

	var pattern = "*"
	if cli.NArg() == 1 {
		pattern = cli.Arg(0)
	}
	iterator, err := newClient(insecureSkipVerify).ListKeys(cancelOnSignal(os.Interrupt, os.Kill), pattern)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to list keys matching %q: %v", pattern, err)
	}

	if !isTerm(os.Stdout) || jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		for iterator.Next() {
			encoder.Encode(iterator.Value())
		}
	} else {
		for iterator.Next() {
			fmt.Println(iterator.Value().Name)
		}
	}
	if err = iterator.Err(); err != nil {
		iterator.Close()
		stdlog.Fatalf("Error: %v", err)
	}
	if err = iterator.Close(); err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
}

const deleteCmdUsage = `Usage:
    kes key delete [options] <name>

Options:
    -k, --insecure         Skip X.509 certificate validation during TLS handshake
    -h, --help             Show list of command-line options

Deletes the key referenced by <name>. Any ciphertext produced by this key cannot
be decrypted anymore.

Examples:
    $ kes key delete my-key
`

func deleteKey(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, deleteCmdUsage) }

	var insecureSkipVerify bool
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		stdlog.Fatal("Error: no key name specified")
	}
	if cli.NArg() > 1 {
		stdlog.Fatal("Error: too many arguments")
	}

	var name = cli.Arg(0)
	if err := newClient(insecureSkipVerify).DeleteKey(cancelOnSignal(os.Interrupt, os.Kill), name); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1) // When the operation is canceled, don't print an error message
		}
		stdlog.Fatalf("Error: failed to delete key %q: %v", name, err)
	}
}
