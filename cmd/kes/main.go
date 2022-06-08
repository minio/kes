// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/sys"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

type commands = map[string]func([]string)

const usage = `Usage:
    kes [options] <command>

Commands:
    server                   Start a KES server.
    init                     Initialize a stateful KES server or cluster.

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
		"init":   initCmd,

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
		buildInfo := sys.BinaryInfo()
		fmt.Printf("kes %s (commit=%s)\n", buildInfo.Version, buildInfo.CommitID)
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
		cli.Fatal("no TLS client certificate. Environment variable 'KES_CLIENT_CERT' is empty")
	}

	keyPath, ok := os.LookupEnv("KES_CLIENT_KEY")
	if !ok {
		cli.Fatal("no TLS private key. Environment variable 'KES_CLIENT_KEY' is not set")
	}
	if strings.TrimSpace(keyPath) == "" {
		cli.Fatal("no TLS private key. Environment variable 'KES_CLIENT_KEY' is empty")
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		cli.Fatalf("failed to load TLS certificate: %v", err)
	}
	certPem, err = xhttp.FilterPEM(certPem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
	if err != nil {
		cli.Fatalf("failed to load TLS certificate: %v", err)
	}
	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		cli.Fatalf("failed to load TLS private key: %v", err)
	}

	// Check whether the private key is encrypted. If so, ask the user
	// to enter the password on the CLI.
	privateKey, err := decodePrivateKey(keyPem)
	if err != nil {
		cli.Fatalf("failed to read TLS private key: %v", err)
	}
	if len(privateKey.Headers) > 0 && x509.IsEncryptedPEMBlock(privateKey) {
		fmt.Fprint(os.Stderr, "Enter password for private key: ")
		password, err := term.ReadPassword(int(os.Stderr.Fd()))
		if err != nil {
			cli.Fatalf("failed to read private key password: %v", err)
		}
		fmt.Fprintln(os.Stderr) // Add the newline again

		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, password)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				cli.Fatalf("incorrect password")
			}
			cli.Fatalf("failed to decrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		cli.Fatalf("failed to load TLS private key or certificate: %v", err)
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

func decodePrivateKey(pemBlock []byte) (*pem.Block, error) {
	ErrNoPrivateKey := errors.New("no PEM-encoded private key found")

	for len(pemBlock) > 0 {
		next, rest := pem.Decode(pemBlock)
		if next == nil {
			return nil, ErrNoPrivateKey
		}
		if next.Type == "PRIVATE KEY" || strings.HasSuffix(next.Type, " PRIVATE KEY") {
			return next, nil
		}
		pemBlock = rest
	}
	return nil, ErrNoPrivateKey
}
