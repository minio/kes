// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	tui "github.com/charmbracelet/lipgloss"
	kesrv "github.com/minio/kes"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/sys"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const usage = `Usage:
    kes [options] <command>

Commands:
    server                   Start a stateful  KES server
    edge                     Start a stateless KES edge server

    cluster                  Manage KES clusters
    enclave                  Manage KES enclaves

    key                      Manage cryptographic keys
    secret                   Manage secrets
    policy                   Manage policies
    identity                 Manage identities

    log                      Print error and audit log events
    status                   Print server status
    metric                   Print server metrics

    migrate                  Migrate KMS data
    update                   Update KES binary

Options:
    -v, --version            Print version information
        --auto-completion    Install auto-completion for this shell
        --soft-hsm           Generate a new software HSM key.
                             The HSM unseals the root key of a cluster

    -h, --help               Print command line options

License:
   Copyright:  MinIO, Inc.
   GNU AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html
`

func main() {
	if complete(filepath.Base(os.Args[0])) {
		return
	}

	cmd := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	subCmds := cli.SubCommands{
		"server": serverCmd,
		"edge":   edgeCmd,

		"cluster": clusterCmd,
		"enclave": enclaveCmd,

		"key":      keyCmd,
		"secret":   secretCmd,
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

	var (
		showVersion    bool
		autoCompletion bool
		softHSM        bool
	)
	cmd.BoolVarP(&showVersion, "version", "v", false, "Print version information.")
	cmd.BoolVar(&autoCompletion, "auto-completion", false, "Install auto-completion for this shell")
	cmd.BoolVar(&softHSM, "soft-hsm", false, "")
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
		const ColorVersion tui.Color = "#2283f3"
		versionColor := tui.NewStyle().Foreground(ColorVersion).Bold(true)
		faint := tui.NewStyle().Faint(true)
		buildInfo := sys.BinaryInfo()

		buf := cli.Buffer{}
		buf.Stylef(versionColor, "Version  : %-22s", buildInfo.Version).Stylef(faint, "commit=%s", buildInfo.CommitID).Sprintln()
		buf.Sprintf("Runtime  : %-22s", runtime.Version()).Stylef(faint, "%s/%s", runtime.GOOS, runtime.GOARCH).Sprintln()
		buf.Sprintf("License  : %-22s", "AGPLv3").Stylef(faint, "https://www.gnu.org/licenses/agpl-3.0.html").Sprintln()
		buf.Sprintf("Copyright: %-22s", "MinIO Inc.").Stylef(faint, "https://min.io").Sprintln()
		cli.Print(buf.String())
		return
	}
	if autoCompletion {
		installAutoCompletion()
		return
	}
	if softHSM {
		hsm, err := kesrv.GenerateSoftHSM(nil)
		if err != nil {
			cli.Fatalf("failed to generate soft HSM key: %v", err)
		}

		bold := tui.NewStyle().Bold(true)
		var buf cli.Buffer
		buf.Sprintln("Your software HSM key:").Sprintln()
		buf.Styleln(bold, "  ", hsm.String()).Sprintln()
		buf.Sprintln("This is the only time it is shown. Keep it secret and secure!").Sprintln()
		buf.Sprintln("The HSM protects your KES cluster as unseal mechanism by decrypting the")
		buf.Sprintln("internal root encryption key ring.")
		buf.Sprintln("Please store it at a secure location. For example your password manager.")
		buf.Sprintln("Without your HSM key you cannot decrypt any data within your KES cluster.")
		cli.Print(buf.String())
		return
	}

	cmd.Usage()
	os.Exit(2)
}

func newClient(insecureSkipVerify bool) *kes.Client {
	endpoints, err := cli.EndpointsFromEnv()
	if err != nil {
		cli.Fatal(err)
	}
	cert, err := cli.CertificateFromEnv(func() ([]byte, error) {
		fmt.Fprint(os.Stderr, "Enter password for private key: ")
		password, err := term.ReadPassword(int(os.Stderr.Fd()))
		if err != nil {
			return nil, fmt.Errorf("failed to read private key password: %v", err)
		}
		fmt.Fprintln(os.Stderr) // Add the newline again
		return password, nil
	})
	if err != nil {
		cli.Fatal(err)
	}
	client := kes.NewClientWithConfig("", &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: insecureSkipVerify,
		CipherSuites:       fips.TLSCiphers(),
		CurvePreferences:   fips.TLSCurveIDs(),
	})
	client.Endpoints = endpoints
	return client
}

func newEnclave(name string, insecureSkipVerify bool) *kes.Enclave {
	client := newClient(insecureSkipVerify)
	if name == "" {
		name = os.Getenv(cli.EnvEnclave)
	}
	return client.Enclave(name)
}

func isTerm(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }
