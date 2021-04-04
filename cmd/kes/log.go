// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/xterm"

	ui "github.com/gizak/termui/v3"
)

const logCmdUsage = `Usage:
    kes log <command>

Commands:
    trace                  Trace server log events.

Options:
    -h, --help             Show list of command-line options.
`

func log(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, logCmdUsage) }
	cli.Parse(args[1:])

	if cli.NArg() == 0 {
		cli.Usage()
		os.Exit(2)
	}

	switch args = cli.Args(); args[0] {
	case "trace":
		logTrace(args)
	default:
		stdlog.Fatalf("Error: %q is not a kes log command. See 'kes log --help'", args[0])
	}
}

const traceLogCmdUsage = `Usage:
    kes log trace [options]

Options:
    --type {audit|error|metric}   Specify the log event type.
                                  Valid options are:
                                    --type=audit (default)
                                    --type=error
                                    --type=metric

    --rate <duration>            Scrap rate when tracing metrics (default: 3s)
    --json                       Print log events as JSON.
    -k, --insecure               Skip X.509 certificate validation during TLS handshake.
    -h, --help                   Show list of command-line options.

Subscribes to the KES server {audit | error | metric} log. If standard
output is a terminal it displays a table-view terminal UI that shows the
stream of log events. Otherwise, or when --json is specified, the log
events are written to standard output in JSON format.

Examples:
    $ kes log trace
`

func logTrace(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprintf(os.Stderr, traceLogCmdUsage) }

	var (
		typeFlag           string
		rateFlag           time.Duration
		jsonOutput         bool
		insecureSkipVerify bool
	)
	cli.StringVar(&typeFlag, "type", "audit", "Log event type [ audit | error | metric ]")
	cli.DurationVar(&rateFlag, "rate", 3*time.Second, "Scrap rate when tracing metrics")
	cli.BoolVar(&jsonOutput, "json", false, "Print log events as JSON")
	cli.BoolVar(&insecureSkipVerify, "k", false, "Skip X.509 certificate validation during TLS handshake")
	cli.BoolVar(&insecureSkipVerify, "insecure", false, "Skip X.509 certificate validation during TLS handshake")
	cli.Parse(args[1:])

	if cli.NArg() > 0 {
		stdlog.Fatal("Error: too many arguments")
	}

	var (
		client = newClient(insecureSkipVerify)
		ctx    = cancelOnSignal(os.Interrupt, os.Kill)
	)
	switch strings.ToLower(typeFlag) {
	case "audit":
		stream, err := client.AuditLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			stdlog.Fatalf("Error: failed to connect to audit log: %v", err)
		}
		defer stream.Close()

		if !isTerm(os.Stdout) || jsonOutput {
			for stream.Next() {
				fmt.Println(string(stream.Bytes()))
			}
			stdlog.Fatalf("Error: audit log closed with: %v", stream.Err())
			return
		}
		traceAuditLogWithUI(stream)
	case "error":
		stream, err := client.ErrorLog(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1) // When the operation is canceled, don't print an error message
			}
			stdlog.Fatalf("Error: failed to connect to error log: %v", err)
		}
		defer stream.Close()

		if !isTerm(os.Stdout) || jsonOutput {
			for stream.Next() {
				fmt.Println(string(stream.Bytes()))
			}
			stdlog.Fatalf("Error: error log closed with: %v", stream.Err())
		}
		traceErrorLogWithUI(stream)
	case "metric":
		if !jsonOutput && isTerm(os.Stdout) {
			traceMetricsWithUI(ctx, client, rateFlag)
			return
		}

		ticker := time.NewTicker(rateFlag)
		defer ticker.Stop()

		encoder := json.NewEncoder(os.Stdout)
		for {
			metrics, err := client.Metrics(ctx)
			if err != nil {
				stdlog.Fatalf("Error: %v", err)
			}
			encoder.Encode(metrics)
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	default:
		stdlog.Fatalf("Error: invalid log type --type: %q", typeFlag)
	}
}

// traceMetricsWithUI iterates scraps the KES metrics
// and prints a table-like UI to STDOUT.
func traceMetricsWithUI(ctx context.Context, client *kes.Client, rate time.Duration) {
	draw := func(t *xterm.Table, m *kes.Metric) {
		N := m.RequestN()

		t.Draw()
		fmt.Printf(" Active : %d\n", m.RequestActive)
		fmt.Printf(" Success: %s%% | %s\n", color.GreenString(fmt.Sprintf("%05.2f", (100*float64(m.RequestOK)/float64(N)))), color.GreenString(strconv.FormatUint(m.RequestOK, 10)))
		fmt.Printf(" Error  : %s%% | %s\n", color.RedString(fmt.Sprintf("%05.2f", (100*float64(m.RequestErr)/float64(N)))), color.RedString(strconv.FormatUint(m.RequestErr, 10)))
		fmt.Printf(" Failure: %s%% | %s\n\n", color.MagentaString(fmt.Sprintf("%05.2f", (100*float64(m.RequestFail)/float64(N)))), color.MagentaString(strconv.FormatUint(m.RequestFail, 10)))
		fmt.Printf(" UpTime : %v\n", m.UpTime)
	}

	var metric kes.Metric
	var table = xterm.NewTable("0-10ms", "10-50ms", "50-100ms", "100-250ms", "250-500ms", "500ms-1s", "1-1.5s", "1.5-3s", "3-5s", "5-10s")
	table.Header()[0].Width = 0.095
	table.Header()[1].Width = 0.095
	table.Header()[2].Width = 0.095
	table.Header()[3].Width = 0.095
	table.Header()[4].Width = 0.095
	table.Header()[5].Width = 0.095
	table.Header()[6].Width = 0.095
	table.Header()[7].Width = 0.095
	table.Header()[8].Width = 0.095
	table.Header()[9].Width = 0.095

	table.Header()[0].Alignment = xterm.AlignCenter
	table.Header()[1].Alignment = xterm.AlignCenter
	table.Header()[2].Alignment = xterm.AlignCenter
	table.Header()[3].Alignment = xterm.AlignCenter
	table.Header()[4].Alignment = xterm.AlignCenter
	table.Header()[5].Alignment = xterm.AlignCenter
	table.Header()[6].Alignment = xterm.AlignCenter
	table.Header()[7].Alignment = xterm.AlignCenter
	table.Header()[8].Alignment = xterm.AlignCenter
	table.Header()[9].Alignment = xterm.AlignCenter

	// Initialize the terminal UI and listen on resize
	// events and Ctrl-C / Escape key events.
	if err := ui.Init(); err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
	defer draw(table, &metric) // Draw the table AFTER closing the UI one more time.
	defer ui.Close()           // Closing the UI cleans the screen.

	ticker := time.NewTicker(rate)
	go func() {
		for {
			var err error
			metric, err = client.Metrics(ctx)
			if err != nil {
				continue
			}

			var (
				latency = map[time.Duration]uint64{
					10 * time.Millisecond:    metric.LatencyHistogram[10*time.Millisecond],
					50 * time.Millisecond:    metric.LatencyHistogram[50*time.Millisecond],
					100 * time.Millisecond:   metric.LatencyHistogram[100*time.Millisecond],
					250 * time.Millisecond:   metric.LatencyHistogram[250*time.Millisecond],
					500 * time.Millisecond:   metric.LatencyHistogram[500*time.Millisecond],
					1000 * time.Millisecond:  metric.LatencyHistogram[1000*time.Millisecond],
					1500 * time.Millisecond:  metric.LatencyHistogram[1500*time.Millisecond],
					3000 * time.Millisecond:  metric.LatencyHistogram[3000*time.Millisecond],
					5000 * time.Millisecond:  metric.LatencyHistogram[5000*time.Millisecond],
					10000 * time.Millisecond: metric.LatencyHistogram[10000*time.Millisecond],
				}
				keys   = make([]time.Duration, 0, len(latency))
				values = make([]uint64, 0, len(latency))
			)
			for k := range latency {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for i, k := range keys {
				if i == 0 {
					values = append(values, latency[k])
				} else {
					values = append(values, latency[k]-latency[keys[i-1]])
				}
			}

			var cells = make([]*xterm.Cell, 0, len(values))
			for _, value := range values {
				cells = append(cells, xterm.NewCell(strconv.FormatUint(value, 10)))
			}
			table.SetRow(0, cells...)
			draw(table, &metric)

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	var events = ui.PollEvents()
	for {
		select {
		case event := <-events:
			switch {
			case event.Type == ui.ResizeEvent:
				draw(table, &metric)
			case event.ID == "<C-c>" || event.ID == "<Escape>":
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// traceAuditLogWithUI iterates over the audit log
// event stream and prints a table-like UI to STDOUT.
//
// Each event is displayed as a new row and the UI is
// automatically adjusted to the terminal window size.
func traceAuditLogWithUI(stream *kes.AuditStream) {
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
		stdlog.Fatalf("Error: %v", err)
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
					fmt.Fprintf(os.Stderr, "Error: audit log stream closed with: %v\n", err)
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
	if err := stream.Err(); err != nil {
		stdlog.Fatalf("Error: audit log stream closed with: %v", err)
	}
}

// traceErrorLogWithUI iterates over the error log
// event stream and prints a table-like UI to STDOUT.
//
// Each event is displayed as a new row and the UI is
// automatically adjusted to the terminal window size.
func traceErrorLogWithUI(stream *kes.ErrorStream) {
	table := xterm.NewTable("Time", "Error")
	table.Header()[0].Width = 0.12
	table.Header()[1].Width = 0.87

	table.Header()[0].Alignment = xterm.AlignCenter
	table.Header()[1].Alignment = xterm.AlignLeft

	// Initialize the terminal UI and listen on resize
	// events and Ctrl-C / Escape key events.
	if err := ui.Init(); err != nil {
		stdlog.Fatalf("Error: %v", err)
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
					fmt.Fprintf(os.Stderr, "Error: error log stream closed with: %v\n", err)
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
	if err := stream.Err(); err != nil {
		stdlog.Fatalf("Error: error log stream closed with: %v", err)
	}
}
