// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
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

    server               Start a kes server.

    key                  Manage secret keys.
    policy               Manage the kes server policies.
    identity             Assign policies to identities.
    audit                Manage the kes server audit logs.                  

    tool                 Run specific key and identity management tools.

  -h, --help             Show this list of command line options.
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
	case "key":
		err = key(args)
	case "identity":
		err = identity(args)
	case "policy":
		err = policy(args)
	case "audit":
		err = audit(args)
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
	if addr, ok := os.LookupEnv("KES_SERVER"); ok {
		return addr
	}
	return "https://127.0.0.1:7373"
}

func loadClientCertificates() ([]tls.Certificate, error) {
	certPath := os.Getenv("KES_CLIENT_TLS_CERT_FILE")
	keyPath := os.Getenv("KES_CLIENT_TLS_KEY_FILE")
	if certPath == "" {
		return nil, errors.New("No client TLS certificate: env KES_CLIENT_TLS_CERT_FILE is not set or empty")
	}
	if keyPath == "" {
		return nil, errors.New("No client TLS private key: env KES_CLIENT_TLS_KEY_FILE is not set or empty")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to load TLS key or cert for client: %v", err)
	}
	return []tls.Certificate{cert}, nil
}

func isTerm(f *os.File) bool { return terminal.IsTerminal(int(f.Fd())) }
