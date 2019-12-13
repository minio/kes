// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"
)

const usage = `usage: %s <command>

    server               Start a key server.

    create               Create a new master key at a key server.
    delete               Delete a master key from a key server.

    derive               Derives a new data key from a master key.
    decrypt              Decrypt a encrypted data key using a master key.

    identity             Assign policies to identities.
    policy               Manage the key server policies.

    tool                 Run specific key and identity management tools.

  -h, --help             Show this list of command line optios.
`

func main() {
	cli := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), usage, cli.Name())
	}
	cli.Parse(os.Args[1:])
	args := cli.Args()

	if len(args) < 1 {
		cli.Usage()
		os.Exit(2)
	}

	var err error
	switch args[0] {
	case "server":
		err = server(args)
	case "create":
		err = createKey(args)
	case "delete":
		err = deleteKey(args)
	case "derive":
		err = deriveKey(args)
	case "decrypt":
		err = decryptKey(args)
	case "identity":
		err = identity(args)
	case "policy":
		err = policy(args)
	case "tool":
		err = tool(args)
	default:
		cli.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(cli.Output(), err)
		os.Exit(1)
	}
}

func parseCommandFlags(f *flag.FlagSet, args []string) []string {
	var parsedArgs []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			f.Parse([]string{arg})
		} else {
			parsedArgs = append(parsedArgs, arg)
		}
	}
	return parsedArgs
}

func isFlagPresent(set *flag.FlagSet, name string) bool {
	found := false
	set.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func serverAddr() string {
	if addr, ok := os.LookupEnv("KEY_SERVER"); ok {
		return addr
	}
	return "https://127.0.0.1:7373"
}

func loadClientCertificates() ([]tls.Certificate, error) {
	certPath := os.Getenv("KEY_CLIENT_TLS_CERT_FILE")
	keyPath := os.Getenv("KEY_CLIENT_TLS_KEY_FILE")
	if certPath == "" {
		return nil, errors.New("No client TLS certificate: env KEY_CLIENT_TLS_CERT_FILE is not set or empty")
	}
	if keyPath == "" {
		return nil, errors.New("No client TLS private key: env KEY_CLIENT_TLS_KEY_FILE is not set or empty")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS key or cert for client: %v", err)
	}
	return []tls.Certificate{cert}, nil
}

func isTerm(f *os.File) bool { return terminal.IsTerminal(int(f.Fd())) }
