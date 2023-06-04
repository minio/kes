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
	"io"
	"os"
	"os/signal"
	"unicode/utf8"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const keyCmdUsage = `Usage:
    kes key <command>

Commands:
    create                   Create a new crypto key
    import                   Import a crypto key
    info                     Get information about a crypto key
    ls                       List crypto keys
    rm                       Delete a crypto key

    encrypt                  Encrypt a message
    decrypt                  Decrypt a ciphertext
    dek                      Generate a new data encryption key (DEK)

Options:
    -h, --help               Print command line options

Examples:
  1. Create a key named 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key create my-key

  2. Encrypt the message 'Hello World' with the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key encrypt my-key 'Hello World'

  3. Get metadata information about the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key info my-key

  4. Delete the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key rm my-key
`

func keyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, keyCmdUsage) }

	subCmds := cli.SubCommands{
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
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Create a key named 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key create my-key

  2. Create the keys 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes key create --enclave tenant-1 foo bar
`

func createKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, createKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key create --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if err := enclave.CreateKey(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				cancel()
				os.Exit(1)
			}
			cli.Fatalf("failed to create key '%s': %v", name, err)
		}
	}
}

const importKeyCmdUsage = `Usage:
    kes key import [options] <name> [<key>]

Options:
    -e, --enclave <name>     Operate within the specified enclave
    -k, --insecure           Skip server certificate verification

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
	if err = enclave.ImportKey(ctx, name, &kes.ImportKeyRequest{Key: key}); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to import %q: %v", name, err)
	}
}

const describeKeyCmdUsage = `Usage:
    kes key info [options] <name>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show metadata of the key named 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key info my-key

  1. Show metadata of the keys 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes key info --enclave tenant-1 foo bar
`

func describeKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key info --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	}

	infos := map[string]*kes.KeyInfo{}
	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if _, ok := infos[name]; ok {
			continue // Avoid fetching a key info twice
		}

		info, err := enclave.DescribeKey(ctx, name)
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to describe key '%s': %v", name, err)
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
					cli.Fatalf("failed to describe key '%s': %v", name, err)
				}
			}
			return
		}
		if err := encoder.Encode(infos); err != nil {
			cli.Fatalf("failed to describe keys: %v", err)
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
		buf.Sprintln("Algorithm :", info.Algorithm)
		buf.Sprintf("Date      : %04d-%02d-%02d %02d:%02d:%02d %s", year, month, day, hour, min, sec, zone).Sprintln()
		buf.Sprintln("Owner     :", info.CreatedBy)
		if i < len(cmd.Args())-1 {
			buf.Sprintln()
		}
	}
	cli.Print(buf.String())
}

const lsKeyCmdUsage = `Usage:
    kes key ls [options] [<prefix>]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. List all key names within the enclave $KES_ENCLAVE.
     $ kes key ls
	
  2. List all key names starting with 'foo' within the enclave 'tenant-1'.
    $ kes key ls --enclave tenant-1 foo
`

func lsKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, lsKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key ls --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes key ls --help'")
	}

	prefix := ""
	if cmd.NArg() == 1 {
		prefix = cmd.Arg(0)
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	iter := kes.ListIter[string]{
		NextFunc: enclave.ListKeys,
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
			cli.Fatalf("failed to list keys: %v", err)
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
			cli.Fatalf("failed to list keys: %v", err)
		}
		return
	}

	if len(names) == 0 {
		return
	}
	var buf cli.Buffer
	if isTerm(os.Stdout) {
		buf.Styleln(tui.NewStyle().Underline(true).Bold(true), "Keys")
	}
	for _, name := range names {
		buf.Sprintln(name)
	}
	cli.Print(buf.String())
}

const rmKeyCmdUsage = `Usage:
    kes key rm [options] <name>...

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Delete the key named 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key rm my-key

  2. Delete the keys 'foo' and 'bar' within the enclave 'tenant-1'.
     $ kes key rm --enclave tenant-1 foo bar
`

func rmKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, rmKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key rm --help'", err)
	}
	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	for _, name := range cmd.Args() {
		if err := enclave.DeleteKey(ctx, name); err != nil {
			if errors.Is(err, context.Canceled) {
				cancel()
				os.Exit(1)
			}
			cli.Fatalf("failed to delete key '%s': %v", name, err)
		}
	}
}

const encryptKeyCmdUsage = `Usage:
    kes key encrypt [options] <name> [<message>]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Encrypt 'Hello World' with the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key encrypt my-key 'Hello World'

  2. Encrypt the content of the file ~/secret.txt with the key 'foo' within the
     enclave 'tenant-1' and write the encrypted data to ~/secret.txt.enc
     $ cat ~/secret.txt | kes key encrypt --enclave tenant-1 foo > ~/secret.txt.enc
`

func encryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, encryptKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key encrypt --help'", err)
	}

	var message []byte
	switch cmd.NArg() {
	case 0:
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	case 1:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			cli.Fatalf("failed to read from stdin: %v", err)
		}
		message = data
	case 2:
		message = []byte(cmd.Arg(1))
	default:
		cli.Fatal("too many arguments. See 'kes key encrypt --help'")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	ciphertext, err := enclave.Encrypt(ctx, cmd.Arg(0), message, nil)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to encrypt: %v", err)
	}

	if !isTerm(os.Stdout) {
		if _, err = os.Stdout.Write(ciphertext); err != nil {
			cli.Fatalf("failed to write to stdout: %v", err)
		}
		return
	}
	w := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	if _, err = w.Write(ciphertext); err != nil {
		cli.Fatalf("failed to write to stdout: %v", err)
	}
	if err = w.Close(); err != nil {
		cli.Fatalf("failed to write to stdout: %v", err)
	}
	cli.Println()
}

const decryptKeyCmdUsage = `Usage:
    kes key decrypt [options] <name> <ciphertext>

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification

    -h, --help               Print command line options

Examples:
  1. Decrypt a ciphertext with the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key decrypt my-key 'Zf64uzl7yDw49/wWpmEO0reSJxhlLuqHArz/NVICus0X1uojYngM/i9F2JrvDW/4GG1mtVsUTwAAAAA='

  2. Decrypt the content of the file ~/secret.txt.enc with the key 'foo' within the
     enclave 'tenant-1' and write the plaintext data to ~/secret.txt
     $ cat ~/secret.txt.enc | kes key decrypt --enclave tenant-1 foo > ~/secret.txt
`

func decryptKeyCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, decryptKeyCmdUsage) }

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
		cli.Fatalf("%v. See 'kes key decrypt --help'", err)
	}
	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	}
	if cmd.NArg() == 1 && isTerm(os.Stdin) {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no ciphertext specified")
	}
	if cmd.NArg() > 2 {
		cli.Fatal("too many arguments. See 'kes key decrypt --help'")
	}

	var ciphertext []byte
	if cmd.NArg() == 1 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			cli.Fatalf("failed to read from stdin: %v", err)
		}
		ciphertext = data
	} else {
		ciphertext = []byte(cmd.Arg(1))
	}
	if utf8.Valid(ciphertext) {
		n, err := base64.StdEncoding.Decode(ciphertext, ciphertext)
		if err != nil {
			cli.Fatalf("invalid ciphertext: %v", err)
		}
		ciphertext = ciphertext[:n]
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	plaintext, err := enclave.Decrypt(ctx, cmd.Arg(0), ciphertext, nil)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to decrypt: %v", err)
	}

	switch {
	case !isTerm(os.Stdout):
		if _, err = os.Stdout.Write(plaintext); err != nil {
			cli.Fatalf("failed to write to stdout: %v", err)
		}
	case utf8.Valid(plaintext):
		cli.Println(string(plaintext))
	default:
		cli.Println("<binary data>")
	}
}

const dekCmdUsage = `Usage:
    kes key dek <name>

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Generate a new data encryption key (DEK) using the key 'my-key' within the enclave $KES_ENCLAVE.
     $ kes key decrypt my-key
	
  2. Generate a new data encryption key (DEK) using the key 'foo' within the enclave 'tenant-1'.
     $ kes key dek my-key --enclave tenant-1
`

func dekCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, dekCmdUsage) }

	var (
		insecureSkipVerify bool
		jsonFlag           bool
		enclaveName        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes key dek --help'", err)
	}

	if cmd.NArg() == 0 {
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no key name specified")
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes key dek --help'")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	key, err := enclave.GenerateKey(ctx, cmd.Arg(0), nil)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to generate encryption key: %v", err)
	}

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		type JSON struct {
			Plaintext  []byte `json:"plaintext"`
			Ciphertext []byte `json:"ciphertext"`
		}
		if err := encoder.Encode(JSON{
			Plaintext:  key.Plaintext,
			Ciphertext: key.Ciphertext,
		}); err != nil {
			cli.Fatalf("failed to generate encryption key: %v", err)
		}
		return
	}

	var buf cli.Buffer
	buf.Sprintln("Plaintext  :", base64.StdEncoding.EncodeToString(key.Plaintext))
	buf.Sprintln("Ciphertext :", base64.StdEncoding.EncodeToString(key.Ciphertext))
	cli.Print(buf.String())
}
