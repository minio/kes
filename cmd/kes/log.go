// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
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

  --type               Specify the log event type. (default: audit)
                       Valid options are:
                          --type=audit  
                          --type=error

  --json               Print log events as JSON.

  -k, --insecure       Skip X.509 certificate validation during TLS handshake.

  -h, --help           Show list of command-line options.
`

func logTrace(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), logTraceCmdUsage, cli.Name())
	}

	var (
		typeFlag   string
		jsonOutput bool

		insecureSkipVerify bool
	)
	cli.StringVar(&typeFlag, "type", "audit", "Log event type [ audit | error ]")
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

	switch strings.ToLower(typeFlag) {
	case "audit":
		return traceAuditLog(client, jsonOutput)
	case "error":
		return traceErrorLog(client, jsonOutput)
	default:
		return fmt.Errorf("Unknown log event type: '%s'", typeFlag)
	}
}

// traceAuditLog tries to subscribe to a KES server audit log
// and prints the received log events.
//
// If jsonFlag is true then traceAuditLog prints the JSON
// representation of each event to STDOUT.
//
// If jsonFlag is false then traceAuditLog prints a table
// representation of each event to STDOUT.
func traceAuditLog(client *kes.Client, jsonFlag bool) error {
	stream, err := client.TraceAuditLog()
	if err != nil {
		return err
	}
	defer stream.Close()
	closeOn(stream, os.Interrupt, os.Kill)

	if !isTerm(os.Stdout) || jsonFlag {
		for stream.Next() {
			fmt.Println(string(stream.Bytes()))
		}
		return stream.Err()
	}

	var (
		none  = color.New()
		bold  = color.New(color.Bold)
		green = color.New(color.FgGreen)
		red   = color.New(color.FgRed)
	)
	fmt.Println(none.Sprint("┌──────────┬────────────┬──────────────────┬───────────────────────────────────┬────────────┐"))
	fmt.Println(bold.Sprint("│ Time     │ Identity   │ Status           │ API Operation                     │ Resp. Time │"))
	fmt.Println(none.Sprint("├──────────┼────────────┼──────────────────┼───────────────────────────────────┼────────────┤"))
	for stream.Next() {
		event := stream.Event()

		var (
			identity   = event.Request.Identity
			status     = fmt.Sprintf("[%d %s]", event.Response.StatusCode, http.StatusText(event.Response.StatusCode))
			path       = event.Request.Path
			hh, mm, ss = event.Time.Clock()
			respTime   string
		)
		identity = align(identity, 10, 10, "…") // make identity exatly 10 chars long (pad with whitespace)
		status = align(status, 16, 16, "…")     // make status exactly 16 chars long (pad with whitespace)
		path = align(path, 33, 33, "…")         // make path exactly 33 chars long (pad with whitespace)

		if event.Response.StatusCode == http.StatusOK {
			status = green.Sprint(status)
		} else {
			status = red.Sprint(status)
		}

		// Truncate duration values such that we show reasonable
		// time values - like 1.05s or 345.76ms.
		switch {
		case event.Response.Time >= time.Second:
			respTime = event.Response.Time.Truncate(10 * time.Millisecond).String()
		case event.Response.Time >= time.Millisecond:
			respTime = event.Response.Time.Truncate(10 * time.Microsecond).String()
		default:
			respTime = event.Response.Time.Truncate(time.Microsecond).String()
		}
		respTime = align(respTime, 10, 10, "")

		// │ Time     │ Identity │ Status   │ API Operation │ Resp. Time │
		// │ 10 chars │ 12 chars │ 18 chars │ 35 chars      │ 12 chars   │
		const format = "│ %02d:%02d:%02d │ %s │ %s │ %s │ %s │"
		fmt.Print("\r") // clear line
		fmt.Println(fmt.Sprintf(format, hh, mm, ss, identity, status, path, respTime))
		fmt.Print("└──────────┴────────────┴──────────────────┴───────────────────────────────────┴────────────┘")
	}
	return stream.Err()
}

// traceErrorLog tries to subscribe to a KES server error log
// and prints the received log events.
//
// If jsonFlag is true then traceErrorLog prints the JSON
// representation of each event to STDOUT.
//
// If jsonFlag is false then traceErrorLog prints a table
// representation of each event to STDOUT.
func traceErrorLog(client *kes.Client, jsonFlag bool) error {
	stream, err := client.TraceErrorLog()
	if err != nil {
		return err
	}
	defer stream.Close()
	closeOn(stream, os.Interrupt, os.Kill)

	if !isTerm(os.Stdout) || jsonFlag {
		for stream.Next() {
			fmt.Println(string(stream.Bytes()))
		}
		return stream.Err()
	}

	var (
		none = color.New()
		bold = color.New(color.Bold)
	)
	fmt.Println(none, "┌──────────┬────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println(bold, "│ Time     │ Error                                                                          │")
	fmt.Println(none, "├──────────┼────────────────────────────────────────────────────────────────────────────────┤")
	for stream.Next() {
		// An error event message has the following form: YY/MM/DD hh/mm/ss <message>.
		// We split this message into 3 segements:
		//  1. YY/MM/DD
		//  2. hh/mm/ss
		//  3. <message>
		// The 2nd segment is the day-time and 3rd segment is the actual error message.
		segements := strings.SplitN(stream.Event().Message, " ", 3)

		fmt.Print("\r") // clear line
		if len(segements) == 3 {
			message := align(segements[2], 78, 78, "")
			timestamp := align(segements[1], 8, 8, "")

			const format = "│ %s │ %s │"
			fmt.Println(fmt.Sprintf(format, timestamp, message))
		} else {
			message := align(stream.Event().Message, 78, 78, "")
			hh, mm, ss := time.Now().Clock()

			const format = "│ %02d:%02d:%02d │ %s │"
			fmt.Println(fmt.Sprintf(format, hh, mm, ss, message))
		}
		fmt.Print("└──────────┴────────────────────────────────────────────────────────────────────────────────┘")
	}
	return stream.Err()
}

// closeOn closes c if one of the given system signals
// occurs. If c.Close() returns an error this error is
// written to STDERR.
func closeOn(c io.Closer, signals ...os.Signal) {
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, signals...)

	go func() {
		<-sigCh
		if err := c.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
}

// align aligns the given text such that is at least
// min and at most max runes long.
//
// If text has fewer than min runes then align appends
// whitespaces to text.
//
// If text has more than max runes then align trims
// text to max runes. In this case align adds the pad
// string to text. In any case the returned string
// has never more then max runes.
func align(text string, min, max int, pad string) string {
	if min > max {
		panic("invalid min > max")
	}
	if max <= 0 {
		panic("invalid max <= 0")
	}
	if len([]rune(pad)) > max {
		panic("invalid len(pad) > max")
	}

	switch s := []rune(text); {
	case len(s) > max:
		return string(s[:max-len([]rune(pad))]) + pad
	case len(s) < min:
		return text + strings.Repeat(" ", min-len(s))
	default:
		return text
	}
}
