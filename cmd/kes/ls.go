// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kms-go/kes"
	flag "github.com/spf13/pflag"
)

const lsUsage = `Usage:
    kes ls [-a KEY] [-k] [--json] [-i] [-p] [-s HOST[:PORT]] [PREFIX]

Options:
    -a, --api-key KEY           API key to authenticate to the KES server.
                                Defaults to $MINIO_KES_API_KEY.
    -s, --server HOST[:PORT]    Use the server HOST[:PORT] instead of
                                $MINIO_KES_SERVER.
        --json                  Print output in JSON format.
    -i, --identity              List identities.
    -p, --policy                List policy names.
    -k, --insecure              Skip server certificate verification.
`

func ls(args []string) {
	var (
		apiKey     string
		skipVerify bool
		jsonOutput bool
		host       string
		policies   bool
		identities bool
	)

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flagsAPIKey(flags, &apiKey)
	flagsInsecureSkipVerify(flags, &skipVerify)
	flagsOutputJSON(flags, &jsonOutput)
	flagsServer(flags, &host)
	flags.BoolVarP(&policies, "policy", "p", false, "")
	flags.BoolVarP(&identities, "identity", "i", false, "")
	flags.Usage = func() { fmt.Fprint(os.Stderr, lsUsage) }

	if err := flags.Parse(args[1:]); err != nil {
		cli.Exit(err)
	}
	if flags.NArg() > 1 {
		cli.Exit("too many arguments")
	}
	if identities && policies {
		cli.Exit("'-p / --policy' and '-i / --identity' must not be used at the same time")
	}

	// Define functions for listing keys, identities and policies.
	// All a []string since we want to print the elements anyway.
	listKeys := func(ctx context.Context, client *kes.Client, prefix string) ([]string, error) {
		iter := kes.ListIter[string]{
			NextFunc: client.ListKeys,
		}
		var names []string
		for name, err := iter.SeekTo(ctx, prefix); err != io.EOF; name, err = iter.Next(ctx) {
			if err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		return names, nil
	}
	listIdentities := func(ctx context.Context, client *kes.Client, prefix string) ([]string, error) {
		iter := kes.ListIter[kes.Identity]{
			NextFunc: client.ListIdentities,
		}
		var names []string
		for id, err := iter.SeekTo(ctx, prefix); err != io.EOF; id, err = iter.Next(ctx) {
			if err != nil {
				return nil, err
			}
			names = append(names, id.String())
		}
		return names, nil
	}
	listPolicies := func(ctx context.Context, client *kes.Client, prefix string) ([]string, error) {
		iter := kes.ListIter[string]{
			NextFunc: client.ListPolicies,
		}
		var names []string
		for name, err := iter.SeekTo(ctx, prefix); err != io.EOF; name, err = iter.Next(ctx) {
			if err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		return names, nil
	}

	var prefix string
	if flags.NArg() == 1 {
		prefix = flags.Arg(0)
	}

	client := newClient(config{
		Endpoint:           host,
		APIKey:             apiKey,
		InsecureSkipVerify: skipVerify,
	})
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var (
		names []string
		err   error
	)
	switch {
	case identities:
		names, err = listIdentities(ctx, client, prefix)
	case policies:
		names, err = listPolicies(ctx, client, prefix)
	default:
		names, err = listKeys(ctx, client, prefix)
	}
	if err != nil {
		cli.Exit(err)
	}
	slices.Sort(names)

	if jsonOutput {
		if err := json.NewEncoder(os.Stdout).Encode(names); err != nil {
			cli.Exit(err)
		}
		return
	}
	if len(names) == 0 {
		return
	}

	buf := &strings.Builder{}
	switch s := tui.NewStyle().Underline(true); {
	case identities:
		fmt.Fprintln(buf, s.Render("Identity"))
	case policies:
		fmt.Fprintln(buf, s.Render("Policy"))
	default:
		fmt.Fprintln(buf, s.Render("Key"))
	}
	for _, name := range names {
		fmt.Fprintln(buf, name)
	}
	fmt.Print(buf)
}
