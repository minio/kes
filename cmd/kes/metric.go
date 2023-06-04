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
	"time"

	"aead.dev/mem"
	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const metricCmdUsage = `Usage:
    kes metric [options]

Options:
    -e, --enclave <name>     Specify the enclave to use. Overwrites $KES_ENCLAVE
    -k, --insecure           Skip server certificate verification
        --rate <duration>    Fetch and show metric updates periodically
        --json               Print result in JSON format

    -h, --help               Print command line options

Examples:
  1. Show a metric summary.
     $ kes metric

  2. Show a metric summary in JSON format.
     $ kes metric --json

  3. Show a metric summary and then display updates every 3 seconds.
     $ kes metric --rate 3s
`

func metricCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, metricCmdUsage) }

	var (
		jsonFlag           bool
		insecureSkipVerify bool
		enclaveName        string
		rate               time.Duration
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print result in JSON format")
	cmd.DurationVar(&rate, "rate", 0, "Fetch and show metric updates periodically")
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.StringVarP(&enclaveName, "enclave", "e", "", "Specify the enclave to use")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes metric --help'", err)
	}
	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes metric --help'")
	}

	enclave := newEnclave(enclaveName, insecureSkipVerify)
	if jsonFlag {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
		metrics, err := enclave.Metrics(ctx)
		cancel()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				os.Exit(1)
			}
			cli.Fatalf("failed to fetch metrics: %v", err)
		}
		if err = json.NewEncoder(os.Stdout).Encode(metrics); err != nil {
			cli.Fatalf("failed to encode metrics: %v", err)
		}
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	metric, err := enclave.Metrics(ctx)
	if err != nil {
		cancel()
		if errors.Is(err, context.Canceled) {
			os.Exit(1)
		}
		cli.Fatalf("failed to fetch metrics: %v", err)
	}
	printMetricSummary(&metric)
	if rate == 0 {
		return
	}

	printHeader := true
	ticker := time.NewTicker(rate)
	defer ticker.Stop()
	for {
		prev := metric
		select {
		case <-ticker.C:
			metric, err = enclave.Metrics(ctx)
			if errors.Is(err, context.Canceled) {
				return
			}
		case <-ctx.Done():
			return
		}
		if err != nil {
			continue
		}
		if printHeader {
			var header cli.Buffer
			header.Sprintln()
			header.Stylef(tui.NewStyle().Bold(true).Underline(true), "%-8s │ %6s │ %6s │ %6s │ %8s", "Time", "Req/s", "Err/s", "CPU", "RAM")
			cli.Println(header.String())
			printHeader = false
		}

		var (
			reqPerSec float64
			errPerSec float64
		)
		if sec := (metric.UpTime - prev.UpTime).Seconds(); sec > 0 {
			reqPerSec = float64(metric.RequestN()-prev.RequestN()) / sec
			errPerSec = float64((metric.RequestErr+metric.RequestFail)-(prev.RequestErr+prev.RequestFail)) / sec
		}
		hour, min, sec := time.Now().Clock()

		cli.Println(fmt.Sprintf("%02d:%02d:%02d │ %6.1f │ %6.1f │ %6d │ %8s ",
			hour, min, sec,
			reqPerSec,
			errPerSec,
			metric.Threads,
			mem.FormatSize(mem.Size(metric.HeapAlloc+metric.StackAlloc), 'D', 2),
		))
	}
}

func printMetricSummary(metrics *kes.Metric) {
	const (
		UptimeColor tui.Color = "#2283f3"
		GreenColor  tui.Color = "#00ff00"
		YellowColor tui.Color = "#ffb703"
		RedColor    tui.Color = "#ff0000"
	)
	uptimeColor := tui.NewStyle().Foreground(UptimeColor)
	green := tui.NewStyle().Foreground(GreenColor)
	yellow := tui.NewStyle().Foreground(YellowColor)
	red := tui.NewStyle().Foreground(RedColor)

	var buf cli.Buffer
	buf.Stylef(uptimeColor, "Uptime     %d days %s", int64(metrics.UpTime/(24*time.Hour)), metrics.UpTime%(24*time.Hour)).Sprintln()
	buf.Sprintf("CPU        %d threads on %d vCPUs", metrics.Threads, metrics.UsableCPUs).Sprintln()

	buf.Sprintln("RAM")
	buf.Sprintf("   heap      %10s", mem.FormatSize(mem.Size(metrics.HeapAlloc), 'D', 2)).Sprintln()
	buf.Sprintf("   stack     %10s", mem.FormatSize(mem.Size(metrics.StackAlloc), 'D', 2)).Sprintln()

	buf.Sprintln("Request")
	buf.Stylef(green, "   OK  [2xx] %10d [ %5.1f%% ]", metrics.RequestOK, 100*(float64(metrics.RequestOK)/float64(metrics.RequestN()))).Sprintln()
	buf.Stylef(yellow, "   Err [4xx] %10d [ %5.1f%% ]", metrics.RequestErr, 100*(float64(metrics.RequestErr)/float64(metrics.RequestN()))).Sprintln()
	buf.Stylef(red, "   Err [5xx] %10d [ %5.1f%% ]", metrics.RequestFail, 100*(float64(metrics.RequestFail)/float64(metrics.RequestN()))).Sprintln()
	buf.Sprintf("   Total     %10d [ 100.0%% ]", metrics.RequestN()).Sprintln()

	buf.Sprintln("Latency")
	latencies := maps.Keys(metrics.LatencyHistogram)
	slices.Sort(latencies)
	for i, latency := range latencies {
		var prev uint64
		if i > 0 {
			prev = metrics.LatencyHistogram[latencies[i-1]]
		}
		n := metrics.LatencyHistogram[latency]
		buf.Sprintf("   %-9s %10d [ %5.1f%% ]", latency, n-prev, 100*float64(n-prev)/float64(metrics.RequestN())).Sprintln()
	}
	cli.Print(buf.String())
}
