// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strconv"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
	"golang.org/x/exp/maps"
)

const clusterCmdUsage = `Usage:
    kes cluster <command>

Commands:
    add                      Expand a cluster by adding a node
    info                     Get information about a cluster
    rm                       Shrink a cluster by removing a node

Options:
    -h, --help               Print command line options

Examples:
  1. Add the node '10.1.2.3:7373' to the cluster.
     $ kes cluster add '10.1.2.3:7373'

  2. Fetch some information about the cluster.
     $ kes cluster info
	
  3. Remove the node '10.1.2.3:7373' from the cluster.
     $ kes cluster rm '10.1.2.3:7373'
`

func clusterCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, clusterCmdUsage) }

	subCmds := cli.SubCommands{
		"add":  expandClusterCmd,
		"info": describeClusterCmd,
		"rm":   shrinkClusterCmd,
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
		cli.Fatalf("%v. See 'kes enclave --help'", err)
	}
	cmd.Usage()
	os.Exit(2)
}

const expandClusterCmdUsage = `Usage:
    kes cluster add [options] <NODE>

Options:
    -k, --insecure           Skip TLS certificate validation

    -h, --help               Print command line options

Examples:
  1. Add the node '10.1.2.3:7373' to the cluster
     $ kes cluster add '10.1.2.3:7373'

  2. Add the node 'kes-3.cluster.local' to the cluster
     $ kes cluster add 'kes-3.cluster.local'
`

func expandClusterCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, expandClusterCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes cluster add --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no node addr specified")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes cluster add --help'")
	}

	endpoint := cmd.Arg(0)
	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := client.ExpandCluster(ctx, endpoint); err != nil {
		if errors.Is(err, context.Canceled) {
			cancel()
			os.Exit(1)
		}
		cli.Fatalf("failed to add cluster node '%s': %v", endpoint, err)
	}
}

const describeClusterCmdUsage = `Usage:
    kes cluster info [options]

Options:
    -k, --insecure           Skip TLS certificate validation
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Fetch some information about the cluster.
     $ kes cluster info
`

func describeClusterCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, describeClusterCmdUsage) }

	var (
		insecureSkipVerify bool
		jsonFlag           bool
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes cluster info --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes cluster info --help'")
	}

	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	info, err := client.DescribeCluster(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			cancel()
			os.Exit(1)
		}
		cli.Fatalf("failed to fetch cluster info: %v", err)
	}
	cancel()

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(info); err != nil {
			cli.Fatalf("failed to fetch cluster info: %v", err)
		}
		return
	}

	ids := maps.Keys(info.Nodes)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	headerStyle := tui.NewStyle().Bold(true).Underline(true)

	var buf cli.Buffer
	buf.Stylef(headerStyle, "%-4s │ %-10s │ %-20s", "ID", "Type", "Endpoint").Sprintln()
	for _, id := range ids {
		kind := "follower"
		if id == info.Leader {
			kind = "leader"
		}
		buf.Sprintf(" %-3s │ %-10s │ %s", strconv.FormatUint(id, 10), kind, info.Nodes[id]).Sprintln()
	}
	cli.Print(buf.String())
}

const shrinkClusterCmdUsage = `Usage:
    kes cluster rm [options] <name>

Options:
    -k, --insecure           Skip TLS certificate validation

    -h, --help               Print command line options

Examples:
  1. Remove the node '10.1.2.3:7373' from the cluster
     $ kes cluster rm '10.1.2.3:7373'

  2. Remove the node 'kes-3.cluster.local' from the cluster
     $ kes cluster rm 'kes-3.cluster.local'
`

func shrinkClusterCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, shrinkClusterCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes cluster rm --help'", err)
	}

	switch {
	case cmd.NArg() == 0:
		cmd.Usage()
		fmt.Fprintln(os.Stderr)
		cli.Fatal("no node address specified")
	case cmd.NArg() > 1:
		cli.Fatal("too many arguments. See 'kes cluster rm --help'")
	}

	endpoint := cmd.Arg(0)
	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if err := client.ShrinkCluster(ctx, endpoint); err != nil {
		if errors.Is(err, context.Canceled) {
			cancel()
			os.Exit(1)
		}
		cli.Fatalf("failed to remove cluster node '%s': %v", endpoint, err)
	}
}
