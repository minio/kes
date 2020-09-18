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
	"github.com/minio/kes/internal/xterm"

	ui "github.com/gizak/termui/v3"
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
		stream, err := client.AuditLog()
		if err != nil {
			return err
		}
		defer stream.Close()

		if !isTerm(os.Stdout) || jsonOutput {
			closeOn(stream, os.Interrupt, os.Kill)
			for stream.Next() {
				fmt.Println(string(stream.Bytes()))
			}
			return stream.Err()
		}
		return traceAuditLogWithUI(stream)
	case "error":
		stream, err := client.ErrorLog()
		if err != nil {
			return err
		}
		defer stream.Close()

		if !isTerm(os.Stdout) || jsonOutput {
			closeOn(stream, os.Interrupt, os.Kill)
			for stream.Next() {
				fmt.Println(string(stream.Bytes()))
			}
			return stream.Err()
		}
		return traceErrorLogWithUI(stream)
	default:
		return fmt.Errorf("Unknown log event type: '%s'", typeFlag)
	}
}

// traceAuditLogWithUI iterates over the audit log
// event stream and prints a table-like UI to STDOUT.
//
// Each event is displayed as a new row and the UI is
// automatically adjusted to the terminal window size.
func traceAuditLogWithUI(stream *kes.AuditStream) error {
	table := xterm.NewTable("Time", "Identity", "Status", "API Operations", "Response")
	table.Header()[0].Width = 0.12
	table.Header()[1].Width = 0.15
	table.Header()[2].Width = 0.15
	table.Header()[3].Width = 0.45
	table.Header()[4].Width = 0.12

	table.Header()[0].Alignment = xterm.AlignCenter
	table.Header()[1].Alignment = xterm.AlignCenter
	table.Header()[2].Alignment = xterm.AlignCenter
	table.Header()[3].Alignment = xterm.AlignLeft
	table.Header()[4].Alignment = xterm.AlignCenter

	// Initialize the terminal UI and listen on resize
	// events and Ctrl-C / Escape key events.
	if err := ui.Init(); err != nil {
		return err
	}
	defer table.Draw() // Draw the table AFTER closing the UI one more time.
	defer ui.Close()   // Closing the UI cleans the screen.

	go func() {
		events := ui.PollEvents()
		for {
			switch event := <-events; {
			case event.Type == ui.ResizeEvent:
				table.Draw()
			case event.ID == "<C-c>" || event.ID == "<Escape>":
				if err := stream.Close(); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
				return
			}
		}
	}()

	var (
		green = color.New(color.FgGreen)
		red   = color.New(color.FgRed)
	)
	table.Draw()
	for stream.Next() {
		event := stream.Event()
		hh, mm, ss := event.Time.Clock()

		var (
			identity = xterm.NewCell(event.Request.Identity)
			status   = xterm.NewCell(fmt.Sprintf("%d %s", event.Response.StatusCode, http.StatusText(event.Response.StatusCode)))
			path     = xterm.NewCell(event.Request.Path)
			reqTime  = xterm.NewCell(fmt.Sprintf("%02d:%02d:%02d", hh, mm, ss))
			respTime *xterm.Cell
		)
		if event.Response.StatusCode == http.StatusOK {
			status.Color = green
		} else {
			status.Color = red
		}

		// Truncate duration values such that we show reasonable
		// time values - like 1.05s or 345.76ms.
		switch {
		case event.Response.Time >= time.Second:
			respTime = xterm.NewCell(event.Response.Time.Truncate(10 * time.Millisecond).String())
		case event.Response.Time >= time.Millisecond:
			respTime = xterm.NewCell(event.Response.Time.Truncate(10 * time.Microsecond).String())
		default:
			respTime = xterm.NewCell(event.Response.Time.Truncate(time.Microsecond).String())
		}

		table.AddRow(reqTime, identity, status, path, respTime)
		table.Draw()
	}
	return stream.Err()
}

// traceErrorLogWithUI iterates over the error log
// event stream and prints a table-like UI to STDOUT.
//
// Each event is displayed as a new row and the UI is
// automatically adjusted to the terminal window size.
func traceErrorLogWithUI(stream *kes.ErrorStream) error {
	table := xterm.NewTable("Time", "Error")
	table.Header()[0].Width = 0.12
	table.Header()[1].Width = 0.87

	table.Header()[0].Alignment = xterm.AlignCenter
	table.Header()[1].Alignment = xterm.AlignLeft

	// Initialize the terminal UI and listen on resize
	// events and Ctrl-C / Escape key events.
	if err := ui.Init(); err != nil {
		return err
	}
	defer table.Draw() // Draw the table AFTER closing the UI one more time.
	defer ui.Close()   // Closing the UI cleans the screen.

	go func() {
		events := ui.PollEvents()
		for {
			switch event := <-events; {
			case event.Type == ui.ResizeEvent:
				table.Draw()
			case event.ID == "<C-c>" || event.ID == "<Escape>":
				if err := stream.Close(); err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
				return
			}
		}
	}()

	table.Draw()
	for stream.Next() {
		// An error event message has the following form: YY/MM/DD hh/mm/ss <message>.
		// We split this message into 3 segments:
		//  1. YY/MM/DD
		//  2. hh/mm/ss
		//  3. <message>
		// The 2nd segment is the day-time and 3rd segment is the actual error message.
		// We replace any '\n' with a whitespace to avoid multi-line table rows.
		segments := strings.SplitN(stream.Event().Message, " ", 3)
		var (
			message *xterm.Cell
			reqTime *xterm.Cell
		)
		if len(segments) == 3 {
			message = xterm.NewCell(strings.ReplaceAll(segments[2], "\n", " "))
			reqTime = xterm.NewCell(segments[1])
		} else {
			hh, mm, ss := time.Now().Clock()

			message = xterm.NewCell(strings.ReplaceAll(stream.Event().Message, "\n", " "))
			reqTime = xterm.NewCell(fmt.Sprintf("%02d:%02d:%02d", hh, mm, ss))
		}
		table.AddRow(reqTime, message)
		table.Draw()
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
