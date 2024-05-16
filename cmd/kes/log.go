// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kms-go/kes"

	flag "github.com/spf13/pflag"
)

const logCmdUsage = `Usage:
    kes log <command>

Options:
    --audit                  Print audit logs. (default)
    --error                  Print error logs.
    --json                   Print log events as JSON.

    -k, --insecure           Skip TLS certificate validation.
    -h, --help               Print command line options.

Examples:
    $ kes log
    $ kes log --error
`

func logCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, logCmdUsage) }

	var (
		auditFlag          bool
		errorFlag          bool
		jsonFlag           bool
		insecureSkipVerify bool
	)
	cmd.BoolVar(&auditFlag, "audit", true, "Print audit logs")
	cmd.BoolVar(&errorFlag, "error", false, "Print error logs")
	cmd.BoolVar(&jsonFlag, "json", false, "Print log events as JSON")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes log --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes key import --help'")
	}
	if auditFlag && errorFlag && cmd.Changed("audit") {
		cli.Fatal("cannot display audit and error logs at the same time")
	}
	if auditFlag && errorFlag { // Unset (default) audit flag if error flag has been set
		auditFlag = !auditFlag
	}

	client := newClient(config{
		InsecureSkipVerify: insecureSkipVerify,
	})
	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	switch {
	case auditFlag:
		stream, err := client.AuditLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to connect to error log: %v", err)
		}
		defer stream.Close()

		if jsonFlag {
			if _, err = stream.WriteTo(os.Stdout); err != nil {
				cli.Fatal(err)
			}
		} else {
			printAuditLog(stream)
		}
	case errorFlag:
		stream, err := client.ErrorLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to connect to error log: %v", err)
		}
		defer stream.Close()

		if jsonFlag {
			if _, err = stream.WriteTo(os.Stdout); err != nil {
				cli.Fatal(err)
			}
		} else {
			printErrorLog(stream)
		}
	default:
		cmd.Usage()
		os.Exit(2)
	}
}

func printAuditLog(stream *kes.AuditStream) {
	var (
		statStyleFail    = tui.NewStyle().Foreground(tui.Color("#ff0000")).Width(5)
		statStyleSuccess = tui.NewStyle().Foreground(tui.Color("#00ff00")).Width(5)
		identityStyle    = tui.NewStyle().Foreground(tui.AdaptiveColor{Light: "#D1BD2E", Dark: "#C6A18C"}).MaxWidth(20).Inline(true)
		apiStyle         = tui.NewStyle().Foreground(tui.AdaptiveColor{Light: "#2E42D1", Dark: "#2e8bc0"}).Width(30).Inline(true)
		ipStyle          = tui.NewStyle().Width(15).Inline(true)
	)
	const (
		header = "Time        Status    Identity                IP                 API                               Latency"
		format = "%02d:%02d:%02d    %s     %s    %s    %s    %s\n"
	)

	if cli.IsTerminal() {
		fmt.Println(tui.NewStyle().Bold(true).Underline(true).Render(header))
	} else {
		fmt.Println(header)
	}
	for stream.Next() {
		event := stream.Event()
		var (
			hour, min, sec = event.Timestamp.Clock()
			status         = strconv.Itoa(event.StatusCode)
			identity       = identityStyle.Render(event.ClientIdentity.String())
			apiPath        = apiStyle.Render(event.APIPath)
			latency        = event.ResponseTime
		)

		if event.StatusCode == http.StatusOK {
			status = statStyleSuccess.Render(status)
		} else {
			status = statStyleFail.Render(status)
		}

		switch {
		case latency >= time.Second:
			latency = latency.Round(100 * time.Millisecond)
		case latency >= 10*time.Millisecond:
			latency = latency.Round(time.Millisecond)
		case latency >= time.Millisecond:
			latency = latency.Round(100 * time.Microsecond)
		case latency >= 10*time.Microsecond:
			latency = latency.Round(time.Microsecond)
		}

		var ipAddr string
		if len(event.ClientIP) == 0 {
			ipAddr = "<unknown>"
		} else {
			ipAddr = event.ClientIP.String()
		}
		ipAddr = ipStyle.Render(ipAddr)

		fmt.Printf(format, hour, min, sec, status, identity, ipAddr, apiPath, latency)
	}
	if err := stream.Close(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}

func printErrorLog(stream *kes.ErrorStream) {
	for stream.Next() {
		fmt.Println(stream.Event().Message)
	}
	if err := stream.Close(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}
