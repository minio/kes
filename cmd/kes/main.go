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
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"strings"

	"github.com/minio/kes"
	"golang.org/x/term"
)

// Use e.g.: go build -ldflags "-X main.version=v1.0.0"
// to set the binary version.
var version = "0.0.0-dev"

const usage = `Usage:
    kes [options] <command>

Commands:
    server                   Starts a KES server.
    key                      Manage secret keys.
    log                      Work with server logs.
    policy                   Manage the kes server policies.
    identity                 Assign policies to identities.
    tool                     Run specific key and identity management tools.

    -v, --version            Print version information.
    -u, --update             Update kes to latest release.
    -h, --help               Show this list of command line options.
`

func main() {
	stdlog.SetFlags(0)
	stdlog.SetOutput(os.Stderr)

	cli := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var showVersion bool
	var update bool
	cli.BoolVar(&showVersion, "v", false, "Print version information.")
	cli.BoolVar(&showVersion, "version", false, "Print version information.")
	cli.BoolVar(&update, "u", false, "Update kes to latest release.")
	cli.BoolVar(&update, "update", false, "Update kes to latest release.")
	cli.Parse(os.Args[1:])

	if showVersion {
		fmt.Println("kes version", version)
		return
	}

	if update {
		if err := updateInplace(); err != nil {
			stdlog.Fatalf("Error: %v\n", err)
		}
		return
	}

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(1)
	}

	switch args := cli.Args(); args[0] {
	case "server":
		server(args)
	case "key":
		keyCmd(args)
	case "log":
		log(args)
	case "identity":
		identity(args)
	case "policy":
		policy(args)
	case "tool":
		tool(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes command. See 'kes --help'", args[0])
	}
}

func newClient(insecureSkipVerify bool) *kes.Client {
	const DefaultServer = "https://127.0.0.1:7373"

	certPath, ok := os.LookupEnv("KES_CLIENT_CERT")
	if !ok {
		stdlog.Fatal("Error: no TLS client certificate. Environment variable 'KES_CLIENT_CERT' is not set")
	}
	if strings.TrimSpace(certPath) == "" {
		stdlog.Fatal("Error: no TLS client certificate. Environment variable 'KES_CLIENT_CERT' is empty")
	}

	keyPath, ok := os.LookupEnv("KES_CLIENT_KEY")
	if !ok {
		stdlog.Fatal("Error: no TLS private key. Environment variable 'KES_CLIENT_KEY' is not set")
	}
	if strings.TrimSpace(keyPath) == "" {
		stdlog.Fatal("Error: no TLS private key. Environment variable 'KES_CLIENT_KEY' is empty")
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		stdlog.Fatalf("Error: failed to load TLS certificate: %v", err)
	}
	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		stdlog.Fatalf("Error: failed to load TLS private key: %v", err)
	}

	// Check whether the private key is encrypted. If so, ask the user
	// to enter the password on the CLI.
	privateKey, rest := pem.Decode(bytes.TrimSpace(keyPem))
	if len(rest) > 0 {
		stdlog.Fatal("Error: failed to load TLS private key: PEM block contains additional unknown data")
	}
	if privateKey.Type != "PRIVATE KEY" && !strings.HasSuffix(privateKey.Type, " PRIVATE KEY") {
		stdlog.Fatalf("Error: failed to load TLS private key: invalid type %q", privateKey.Type)
	}
	if len(privateKey.Headers) > 0 && x509.IsEncryptedPEMBlock(privateKey) {
		fmt.Print("Enter password for private key: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			stdlog.Fatalf("Error: failed to read private key password: %v", err)
		}
		fmt.Println() // Add the newline again

		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, password)
		if err != nil {
			if errors.Is(err, x509.IncorrectPasswordError) {
				stdlog.Fatalf("Error: incorrect password")
			}
			stdlog.Fatalf("Error: failed to decrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		stdlog.Fatalf("Error: failed to load TLS private key or certificate: %v", err)
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

type multiFlag []string

var _ flag.Value = (*multiFlag)(nil) // compiler check

func (f *multiFlag) String() string { return fmt.Sprint(*f) }

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
