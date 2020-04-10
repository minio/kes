// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/fatih/color"
)

const logCmdUsage = `usage: %s <command>

    trace              Trace server log events.

  -h, --help           Show list of command-line options.
`

func log(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), logCmdUsage, cli.Name())
	}

	cli.Parse(args[1:])
	if args = cli.Args(); len(args) == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args[0] {
	case "trace":
		return logTrace(args)
	default:
		cli.Usage()
		os.Exit(2)
		return nil // for the compiler
	}
}

const logTraceCmdUsage = `Trace server log events.

Connects to a KES server and traces log events.

usage: %s [flags]

  --json               Print log events as JSON.

  -k, --insecure       Skip X.509 certificate validation during TLS handshake.

  -h, --help           Show list of command-line options.
`

func logTrace(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), logTraceCmdUsage, cli.Name())
	}

	var jsonOutput bool
	var insecureSkipVerify bool
	cli.BoolVar(&jsonOutput, "json", false, "Print log events as JSON")
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	if args = parseCommandFlags(cli, args[1:]); len(args) != 0 {
		cli.Usage()
		os.Exit(2)
	}

	client, err := newClient(insecureSkipVerify)
	if err != nil {
		return err
	}
	stream, err := client.TraceAuditLog()
	if err != nil {
		return err
	}
	defer stream.Close()

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		if err := stream.Close(); err != nil {
			fmt.Fprintln(cli.Output(), err)
		}
	}()

	isTerminal := isTerm(os.Stdout)
	for stream.Next() {
		if !isTerminal || jsonOutput {
			fmt.Println(string(stream.Bytes()))
			continue
		}

		event := stream.Event()
		identity := event.Request.Identity
		if len(identity) > 7 {
			identity = identity[:7]
		}

		var status string
		if runtime.GOOS == "windows" { // don't colorize on windows
			status = fmt.Sprintf("[%d %s]", event.Response.StatusCode, http.StatusText(event.Response.StatusCode))
		} else {
			identity = color.YellowString(identity)
			if event.Response.StatusCode == http.StatusOK {
				status = color.GreenString("[%d %s]", event.Response.StatusCode, http.StatusText(event.Response.StatusCode))
			} else {
				status = color.RedString("[%d %s]", event.Response.StatusCode, http.StatusText(event.Response.StatusCode))
			}
		}

		// Truncate duration values such that we show reasonable
		// time values - like 1.05s or 345.76ms.
		respTime := event.Response.Time
		switch {
		case respTime >= time.Second:
			respTime = respTime.Truncate(10 * time.Millisecond)
		case respTime >= time.Millisecond:
			respTime = respTime.Truncate(10 * time.Microsecond)
		default:
			respTime = respTime.Truncate(time.Microsecond)
		}

		const format = "%s %s %-25s %10s\n"
		fmt.Printf(format, identity, status, event.Request.Path, respTime)
	}
	return stream.Err()
}
