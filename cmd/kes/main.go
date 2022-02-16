// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

// Use e.g.: go build -ldflags "-X main.version=v1.0.0"
// to set the binary version.
var version = "0.0.0-dev"

type commands = map[string]func([]string)

const usage = `Usage:
    kes [options] <command>

Commands:
    server                   Start a KES server.

    key                      Manage cryptographic keys.
    policy                   Manage KES policies.
    identity                 Manage KES identities.

    log                      Print error and audit log events.
    status                   Print server status.
    metric                   Print server metrics.

    migrate                  Migrate KMS data.
    update                   Update KES binary.

Options:
    -v, --version            Print version information.
    -h, --help               Print command line options.
`

func main() {
	cmd := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	subCmds := commands{
		"server": serverCmd,

		"key":      keyCmd,
		"policy":   policyCmd,
		"identity": identityCmd,

		"log":    logCmd,
		"status": statusCmd,
		"metric": metricCmd,

		"migrate": migrateCmd,
		"update":  updateCmd,
	}

	if len(os.Args) < 2 {
		cmd.Usage()
		os.Exit(2)
	}
	if subCmd, ok := subCmds[os.Args[1]]; ok {
		subCmd(os.Args[1:])
		return
	}

	var showVersion bool
	cmd.BoolVarP(&showVersion, "version", "v", false, "Print version information.")
	if err := cmd.Parse(os.Args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes --help'", err)

	}
	if cmd.NArg() > 1 {
		cli.Fatalf("%q is not a kes command. See 'kes --help'", cmd.Arg(1))
	}
	if showVersion {
		fmt.Println("kes version", version)
		return
	}
	cmd.Usage()
	os.Exit(2)
}

func newClient(insecureSkipVerify bool) *kes.Client {
	const DefaultServer = "https://127.0.0.1:7373"

	certPath, ok := os.LookupEnv("KES_CLIENT_CERT")
	if !ok {
		cli.Fatal("no TLS client certificate. Environment variable 'KES_CLIENT_CERT' is not set")
	}
	if strings.TrimSpace(certPath) == "" {
		cli.Fatal("Error: no TLS client certificate. Environment variable 'KES_CLIENT_CERT' is empty")
	}

	keyPath, ok := os.LookupEnv("KES_CLIENT_KEY")
	if !ok {
		cli.Fatal("Error: no TLS private key. Environment variable 'KES_CLIENT_KEY' is not set")
	}
	if strings.TrimSpace(keyPath) == "" {
		cli.Fatal("Error: no TLS private key. Environment variable 'KES_CLIENT_KEY' is empty")
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		cli.Fatalf("Error: failed to load TLS certificate: %v", err)
	}
	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		cli.Fatalf("Error: failed to load TLS private key: %v", err)
	}

	// Check whether the private key is encrypted. If so, ask the user
	// to enter the password on the CLI.
	privateKey, rest := pem.Decode(bytes.TrimSpace(keyPem))
	if len(rest) > 0 {
		cli.Fatal("Error: failed to load TLS private key: PEM block contains additional unknown data")
	}
	if privateKey.Type != "PRIVATE KEY" && !strings.HasSuffix(privateKey.Type, " PRIVATE KEY") {
		cli.Fatalf("Error: failed to load TLS private key: invalid type %q", privateKey.Type)
	}
	if len(privateKey.Headers) > 0 && x509.IsEncryptedPEMBlock(privateKey) {
		fmt.Fprint(os.Stderr, "Enter password for private key: ")
		password, err := term.ReadPassword(int(os.Stderr.Fd()))
		if err != nil {
			cli.Fatalf("Error: failed to read private key password: %v", err)
		}
		fmt.Fprintln(os.Stderr) // Add the newline again

		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, password)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				cli.Fatalf("Error: incorrect password")
			}
			cli.Fatalf("Error: failed to decrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		cli.Fatalf("Error: failed to load TLS private key or certificate: %v", err)
	}

	addr := DefaultServer
	if env, ok := os.LookupEnv("KES_SERVER"); ok {
		addr = env
	}
	return kes.NewClientWithConfig(addr, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: insecureSkipVerify,
	})
}

func isTerm(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
