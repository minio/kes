// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const statusCmdUsage = `Usage:
    kes status [options]

Options:
    -k, --insecure           Skip TLS certificate validation
    -h, --help               Print command line options.
`

func statusCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, statusCmdUsage) }

	var insecureSkipVerify bool
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes status --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes status --help'")
	}

	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	start := time.Now()
	status, err := client.Status(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
	latency := time.Since(start)

	if isTerm(os.Stdout) {
		boldBlue := color.New(color.Bold, color.FgBlue)
		fmt.Println(color.GreenString("●  ") + boldBlue.Sprint(strings.TrimPrefix(client.Endpoints[0], "https://")))
		switch {
		case status.UpTime > 24*time.Hour:
			fmt.Printf("   UpTime:  %.f days %.f hours\n", status.UpTime.Hours()/24, math.Mod(status.UpTime.Hours(), 24))
		case status.UpTime > 1*time.Hour:
			fmt.Printf("   UpTime:  %.f hours\n", status.UpTime.Hours())
		case status.UpTime > 1*time.Minute:
			fmt.Printf("   UpTime:  %.f minutes\n", status.UpTime.Minutes())
		default:
			fmt.Printf("   UpTime: %.f seconds\n", status.UpTime.Seconds())
		}
		fmt.Println("   Latency:", latency.Round(time.Millisecond))
		fmt.Println("   Version:", status.Version)
	} else {
		json.NewEncoder(os.Stdout).Encode(status)
	}
}
