// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/internal/sys/fs"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
)

const initCmdUsage = `Usage:
    kes init [options] <PATH>

Options:
    --config <PATH>          Path to the initial configuration file.
	
    -f, --force              Overwrite any existing data.

    -h, --help               Print command line options.

Examples:
   $ kes init --config init.yml ~/kes
`

func initCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, initCmdUsage) }

	var (
		forceFlag  bool
		configFlag string
	)
	cmd.BoolVarP(&forceFlag, "force", "f", false, "Overwrite any existing data")
	cmd.StringVar(&configFlag, "config", "", "Path to the initial configuration file")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes init --help'", err)
	}

	if cmd.NArg() == 0 {
		cli.Fatal("no path specified. See 'kes init --help'")
	}

	path := cmd.Arg(0)
	switch stat, err := os.Stat(path); {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		cli.Fatalf("failed to access '%s': %v", path, err)
	case err == nil && stat.IsDir() && !forceFlag:
		cli.Fatalf("'%s' already exists. Use 'kes init --force'", path)
	case err == nil && !stat.IsDir() && !forceFlag:
		cli.Fatalf("'%s' already exists and is not a directory. Use 'kes init --force'", path)
	case err == nil && forceFlag:
		if err = os.RemoveAll(path); err != nil {
			cli.Fatalf("failed to remove '%s': %v", path, err)
		}
	}

	config, err := cli.ReadInitConfig(configFlag)
	if err != nil {
		cli.Fatalf("failed to read init config: %v", err)
	}
	if config.System.Admin.Identity.Value().IsUnknown() {
		cli.Fatal("invalid configuration: system identity cannot be empty")
	}

	if _, err = http.LoadCertificate(config.TLS.Certificate.Value(), config.TLS.PrivateKey.Value(), config.TLS.Password.Value()); err != nil {
		cli.Fatalf("failed to load TLS certificate: %v", err)
	}

	sealer, err := sys.SealFromEnvironment(config.Unseal.Environment.Name)
	if err != nil {
		cli.Fatalf("failed to create sealer: %v", err)
	}
	init := &fs.InitConfig{
		Address:           config.Address,
		PrivateKey:        config.TLS.PrivateKey,
		Certificate:       config.TLS.Certificate,
		Password:          config.TLS.Password,
		VerifyClientCerts: config.TLS.Client.VerifyCerts,
	}
	seal := &fs.SealConfig{
		SysAdmin: config.System.Admin.Identity.Value(),
		Sealer:   sealer,
	}
	vault, _, err := fs.Init(cmd.Arg(0), init, seal)
	if err != nil {
		cli.Fatalf("failed to initialize FS Vault: %v", err)
	}

	if len(config.Enclave) == 0 {
		cli.Fatal("no enclave configuration specified")
	}
	for name, enclave := range config.Enclave {
		if enclave.Admin.Identity.Value().IsUnknown() {
			cli.Fatalf("failed to create enclave '%s': no admin identity", name)
		}
		_, err = vault.CreateEnclave(context.Background(), name, enclave.Admin.Identity.Value())
		if err != nil {
			cli.Fatalf("failed to create enclave '%s': %v", name, err)
		}

		enc, err := vault.GetEnclave(context.Background(), name)
		if err != nil {
			cli.Fatalf("failed to init enclave '%s': %v", name, err)
		}
		for policyName, policy := range enclave.Policy {
			err = enc.SetPolicy(context.Background(), policyName, &auth.Policy{
				Allow:     policy.Allow,
				Deny:      policy.Deny,
				CreatedAt: time.Now().UTC(),
				CreatedBy: config.System.Admin.Identity.Value(),
			})
			if err != nil {
				cli.Fatalf("failed to init enclave '%s': failed to create policy '%s': %v", name, policyName, err)
			}
		}
	}

	width := 70
	if isTerm(os.Stdout) {
		w, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil {
			width = w - 2
		}
	}
	{
		header := tui.NewStyle().Underline(true).Bold(true).Foreground(tui.Color("#D1BD2E"))
		item := tui.NewStyle().Bold(true)
		cli.Println(header.Render("TLS:"))
		cli.Println(item.Render("  · Private Key: "), config.TLS.PrivateKey.Value())
		cli.Println(item.Render("  · Certificate: "), config.TLS.Certificate.Value())
		cli.Println()
	}
	{
		header := tui.NewStyle().Underline(true).Bold(true).Foreground(tui.Color("#D1BD2E"))
		item := tui.NewStyle().Bold(true)
		cli.Println(header.Render("System:"))
		cli.Println(item.Render("  · Identity: "), config.System.Admin.Identity.Value())
		cli.Println()
	}
	{
		header := tui.NewStyle().Underline(true).Bold(true).Foreground(tui.Color("#D1BD2E"))
		item := tui.NewStyle().Bold(true)
		cli.Println(header.Render("Unseal:"))
		cli.Println(item.Render("  · Environment: "), config.Unseal.Environment.Name)
		cli.Println()
	}
	{
		border := tui.NewStyle().Border(tui.RoundedBorder(), true, true, true, true).BorderForeground(tui.Color("#007700")).Width(width).Align(tui.Center)
		bold := tui.NewStyle().Bold(true)
		cli.Println(border.Render(fmt.Sprintf(
			"Initialized KES %s in %s",
			bold.Render(sys.BinaryInfo().Version),
			bold.Render(cmd.Arg(0)),
		)))
	}
}
