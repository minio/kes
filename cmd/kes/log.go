// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"

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
	cmd.Usage = func() { fmt.Fprintf(os.Stderr, logCmdUsage) }

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

	client := newClient(insecureSkipVerify)
	ctx, cancelCtx := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancelCtx()

	switch {
	case auditFlag:
		stream, err := client.AuditLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			cli.Fatalf("failed to connect to error log: %v", err)
		}
		defer stream.Close()

		if jsonFlag {
			printAuditJSON(ctx, stream)
		} else {
			printAuditLog(ctx, stream)
		}
	case errorFlag:
		stream, err := client.ErrorLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			cli.Fatalf("failed to connect to error log: %v", err)
		}
		defer stream.Close()

		if jsonFlag {
			printErrorJSON(ctx, stream)
		} else {
			printErrorLog(ctx, stream)
		}
	default:
		cmd.Usage()
		os.Exit(2)
	}
}

func printAuditJSON(ctx context.Context, stream *kes.AuditStream) {
	for stream.Next() {
		fmt.Println(string(stream.Bytes()))
	}
	if err := stream.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}

func printAuditLog(ctx context.Context, stream *kes.AuditStream) {
	var (
		red      = tui.NewStyle().Foreground(tui.Color("#800000")).Width(5)
		green    = tui.NewStyle().Foreground(tui.Color("#008000")).Width(5)
		orange20 = tui.NewStyle().Foreground(tui.Color("#ff8300")).MaxWidth(20)
		blue     = tui.NewStyle().Foreground(tui.Color("#2e8bc0")).Width(30)
		ipStyle  = tui.NewStyle().Width(15).MaxWidth(15)
	)
	const (
		header = "Time        Status    Identity                IP                 API                               Latency"
		format = "%02d:%02d:%02d    %s     %s    %s    %s    %s\n"
	)

	if isTerm(os.Stdout) {
		fmt.Println(tui.NewStyle().Bold(true).Render(header))
	} else {
		fmt.Println(header)
	}
	for stream.Next() {
		event := stream.Event()
		if len(event.Request.IP) == 0 {
			event.Request.IP = net.IPv4(0, 0, 0, 0)
		}
		var (
			hour, min, sec = event.Time.Clock()
			status         = strconv.Itoa(event.Response.StatusCode)
			ip             = ipStyle.Render(event.Request.IP.String())
			identity       = orange20.Render(event.Request.Identity)
			apiPath        = blue.Render(event.Request.Path)
			latency        = event.Response.Time
		)

		if event.Response.StatusCode == http.StatusOK {
			status = green.Render(status)
		} else {
			status = red.Render(status)
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
		fmt.Printf(format, hour, min, sec, status, identity, ip, apiPath, latency)
	}
	if err := stream.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}

func printErrorJSON(ctx context.Context, stream *kes.ErrorStream) {
	for stream.Next() {
		fmt.Println(string(stream.Bytes()))
	}
	if err := stream.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}

func printErrorLog(ctx context.Context, stream *kes.ErrorStream) {
	for stream.Next() {
		fmt.Printf(stream.Event().Message)
	}
	if err := stream.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatal(err)
	}
}
