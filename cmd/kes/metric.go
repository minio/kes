// Copyright 2022 - MinIO, Inc. All rights reserved.
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
	"time"

	"github.com/fatih/color"
	ui "github.com/gizak/termui/v3"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const metricCmdUsage = `Usage:
    kes metric [options]

Options:
    --rate                   Scrap rate when monitoring metrics. (default: 5s)

    -k, --insecure           Skip TLS certificate validation
    -h, --help               Print command line options.
`

func metricCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, metricCmdUsage) }

	var (
		rate               time.Duration
		insecureSkipVerify bool
	)
	cmd.DurationVar(&rate, "rate", 5*time.Second, "Scrap rate when monitoring metrics")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes metric --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes metric --help'")
	}

	client := newClient(insecureSkipVerify)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	if isTerm(os.Stdout) {
		traceMetricsWithUI(ctx, client, rate)
		return
	}

	ticker := time.NewTicker(rate)
	defer ticker.Stop()

	encoder := json.NewEncoder(os.Stdout)
	for {
		metrics, err := client.Metrics(ctx)
		if err != nil {
			cli.Fatalf("failed to fetch metrics: %v", err)
		}
		encoder.Encode(metrics)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// traceMetricsWithUI iterates scraps the KES metrics
// and prints a table-like UI to STDOUT.
func traceMetricsWithUI(ctx context.Context, client *kes.Client, rate time.Duration) {
	draw := func(version string, table *cli.Table, metric *kes.Metric, reqRate float64) {
		var (
			green  = color.New(color.FgGreen)
			yellow = color.New(color.FgYellow)
			red    = color.New(color.FgRed)
			bold   = color.New(color.Bold)
		)

		table.SetRow(0, &cli.Cell{Text: "Success", Color: green}, &cli.Cell{Text: fmt.Sprintf("%05.2f%%", 100*float64(metric.RequestOK)/float64(metric.RequestN())), Color: green}, &cli.Cell{Text: strconv.FormatUint(metric.RequestOK, 10), Color: green})
		table.SetRow(1, &cli.Cell{Text: "Error  ", Color: yellow}, &cli.Cell{Text: fmt.Sprintf("%05.2f%%", 100*float64(metric.RequestErr)/float64(metric.RequestN())), Color: yellow}, &cli.Cell{Text: strconv.FormatUint(metric.RequestErr, 10), Color: yellow})
		table.SetRow(2, &cli.Cell{Text: "Failure", Color: red}, &cli.Cell{Text: fmt.Sprintf("%05.2f%%", 100*float64(metric.RequestFail)/float64(metric.RequestN())), Color: red}, &cli.Cell{Text: strconv.FormatUint(metric.RequestFail, 10), Color: red})
		table.SetRow(3, cli.NewCell("Active "), cli.NewCell(""), cli.NewCell(strconv.FormatUint(metric.RequestActive, 10)))
		table.SetRow(4, cli.NewCell("Rate   "), cli.NewCell(""), cli.NewCell(fmt.Sprintf("%6.1f R/s", reqRate)))
		table.SetRow(5, cli.NewCell("Latency"), cli.NewCell(""), cli.NewCell(avgLatency(metric.LatencyHistogram).Round(time.Millisecond).String()+" Ø"))

		table.Draw()
		fmt.Println()
		if len(client.Endpoints) == 1 {
			fmt.Println(bold.Sprint(" Endpoint:     "), client.Endpoints[0])
		} else {
			fmt.Println(bold.Sprint(" Endpoints:    "), client.Endpoints)
		}
		fmt.Println(bold.Sprint(" Version:      "), version)
		fmt.Println()
		fmt.Println(bold.Sprint(" UpTime:       "), metric.UpTime)
		fmt.Println(bold.Sprint(" Audit Events: "), metric.AuditEvents)
		fmt.Println(bold.Sprint(" Error Events: "), metric.ErrorEvents)
	}
	var (
		metric     kes.Metric
		version, _ = client.Version(ctx)
		table      = cli.NewTable("Request", "Percentage", "Total")
		requestN   uint64
		reqRate    float64
	)
	table.Header()[0].Width = 0.333
	table.Header()[1].Width = 0.333
	table.Header()[2].Width = 0.333

	table.Header()[0].Alignment = cli.AlignCenter
	table.Header()[1].Alignment = cli.AlignCenter
	table.Header()[2].Alignment = cli.AlignCenter

	// Initialize the terminal UI and listen on resize
	// events and Ctrl-C / Escape key events.
	if err := ui.Init(); err != nil {
		cli.Fatal(err)
	}
	defer draw(version, table, &metric, 0) // Draw the table AFTER closing the UI one more time.
	defer ui.Close()                       // Closing the UI cleans the screen.

	ticker := time.NewTicker(rate)
	go func() {
		for {
			var err error
			metric, err = client.Metrics(ctx)
			if err != nil {
				continue
			}

			// Compute the current request rate
			if requestN == 0 {
				requestN = metric.RequestN()
			}
			reqRate = float64(metric.RequestN()-requestN) / rate.Seconds()
			requestN = metric.RequestN()

			draw(version, table, &metric, reqRate)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()

	events := ui.PollEvents()
	for {
		select {
		case event := <-events:
			switch {
			case event.Type == ui.ResizeEvent:
				draw(version, table, &metric, reqRate)
			case event.ID == "<C-c>" || event.ID == "<Escape>":
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// avgLatency computes the arithmetic mean latency o
func avgLatency(histogram map[time.Duration]uint64) time.Duration {
	latencies := make([]time.Duration, 0, len(histogram))
	for l := range histogram {
		latencies = append(latencies, l)
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	// Compute the total number of requests in the histogram
	var N uint64
	for _, l := range latencies {
		N += histogram[l] - N
	}

	var (
		avg float64
		n   uint64
	)
	for _, l := range latencies {
		avg += float64(l) * (float64(histogram[l]-n) / float64(N))
		n += histogram[l] - n
	}
	return time.Duration(avg)
}
