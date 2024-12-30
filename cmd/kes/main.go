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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kms-go/kes"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

type commands = map[string]func([]string)

const usage = `Usage:
    kes [options] <command>

Commands:
    server                   Start a KES server.

    ls                       List keys, policies and identites.
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
        --auto-completion    Install auto-completion for this shell.
    -h, --help               Print command line options.
`

func main() {
	if complete(filepath.Base(os.Args[0])) {
		return
	}

	cmd := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	subCmds := commands{
		"server": serverCmd,

		"ls":       ls,
		"key":      keyCmd,
		"policy":   policyCmd,
		"identity": identityCmd,

		"log":    logCmd,
		"status": statusCmd,
		"metric": metricCmd,

		"migrate": migrate,
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

	var (
		showVersion    bool
		autoCompletion bool
	)
	cmd.BoolVarP(&showVersion, "version", "v", false, "Print version information.")
	cmd.BoolVar(&autoCompletion, "auto-completion", false, "Install auto-completion for this shell")
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
		info, err := sys.ReadBinaryInfo()
		if err != nil {
			cli.Fatal(err)
		}

		faint := tui.NewStyle().Faint(true)
		buf := &strings.Builder{}
		fmt.Fprintf(buf, "Version    %-22s %s\n", info.Version, faint.Render("commit="+info.CommitID))
		fmt.Fprintf(buf, "Runtime    %-22s %s\n", fmt.Sprintf("%s %s/%s", info.Runtime, runtime.GOOS, runtime.GOARCH), faint.Render("compiler="+info.Compiler))
		fmt.Fprintf(buf, "License    %-22s %s\n", "AGPLv3", faint.Render("https://www.gnu.org/licenses/agpl-3.0.html"))
		fmt.Fprintf(buf, "Copyright  %-22s %s\n", fmt.Sprintf("2015-%d MinIO Inc.", time.Now().Year()), faint.Render("https://min.io"))
		fmt.Print(buf.String())
		return
	}

	if autoCompletion {
		installAutoCompletion()
		return
	}

	cmd.Usage()
	os.Exit(2)
}

// config is a structure containing configuration for a client.
type config struct {
	Endpoint           string
	APIKey             string
	PrivateKeyFile     string
	CertificateFile    string
	InsecureSkipVerify bool
}

// newClient returns a new client using the given config.
// On error, it aborts the program using cli.Exit.
func newClient(conf config) *kes.Client {
	var (
		endpoints = strings.Split(conf.Endpoint, ",")
		apiKey    = conf.APIKey
		keyFile   = conf.PrivateKeyFile
		certFile  = conf.CertificateFile
	)

	if conf.Endpoint == "" {
		endpoints = strings.Split(cli.Env(cli.EnvServer), ",")
	}
	for i := range endpoints {
		endpoints[i] = strings.TrimSpace(endpoints[i])
		endpoints[i] = strings.TrimPrefix(endpoints[i], "http://")
		if !strings.HasPrefix(endpoints[i], "https://") {
			endpoints[i] = "https://" + endpoints[i]
		}
	}
	if len(endpoints) == 0 {
		cli.Exitf("'%s' contains no hosts / IPs", cli.EnvServer)
	}

	if apiKey == "" {
		apiKey = cli.Env(cli.EnvAPIKey)
	}
	if keyFile == "" {
		keyFile = cli.Env(cli.EnvPrivateKey)
	}
	if certFile == "" {
		certFile = cli.Env(cli.EnvCertificate)
	}

	if apiKey == "" && keyFile == "" && certFile == "" {
		cli.Exitf("no API key specified. Consider setting %s", cli.EnvAPIKey)
	}
	if apiKey != "" && keyFile != "" {
		cli.Exit("API key and private key file cannot be used at the same time")
	}
	if apiKey != "" && certFile != "" {
		cli.Exit("API key and certificate file cannot be used at the same time")
	}
	if keyFile != "" && certFile == "" {
		cli.Exitf("no certificate file specified. Consider setting %s", cli.EnvCertificate)
	}
	if keyFile == "" && certFile != "" {
		cli.Exitf("no private key file specified. Consider setting %s", cli.EnvPrivateKey)
	}

	var cert tls.Certificate
	if apiKey != "" {
		key, err := kes.ParseAPIKey(apiKey)
		if err != nil {
			cli.Exitf("parsing API key: %v", err)
		}
		if cert, err = kes.GenerateCertificate(key); err != nil {
			cli.Exitf("generating certificate: %v", err)
		}
	} else {
		certPem, err := os.ReadFile(certFile)
		if err != nil {
			cli.Fatalf("reading certificate file: %v", err)
		}
		certPem, err = https.FilterPEM(certPem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
		if err != nil {
			cli.Fatalf("reading certificate file: %v", err)
		}
		keyPem, err := os.ReadFile(keyFile)
		if err != nil {
			cli.Fatalf("reading private key file: %v", err)
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
				cli.Exitf("reading password: %v", err)
			}
			fmt.Fprintln(os.Stderr) // Add the newline again

			decPrivateKey, err := x509.DecryptPEMBlock(privateKey, password)
			if err != nil {
				if errors.Is(err, x509.IncorrectPasswordError) {
					cli.Exit("incorrect password")
				}
				cli.Exitf("failed to decrypt private key: %v", err)
			}
			keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
		}

		if cert, err = tls.X509KeyPair(certPem, keyPem); err != nil {
			cli.Exit(err)
		}
	}

	client := kes.NewClientWithConfig("", &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
		InsecureSkipVerify: conf.InsecureSkipVerify,
	})
	client.Endpoints = endpoints
	return client
}

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
