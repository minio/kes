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
	"sync"
	"time"

	"aead.dev/mem"
	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kms-go/kes"
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
	const (
		EraseLine  = "\033[2K" + "\033[F" + "\r"
		ShowCursor = "\x1b[?25h"
		HideCursor = "\x1b[?25l"
	)
	var (
		header = tui.NewStyle().Bold(true).Faint(true)
		green  = tui.NewStyle().Bold(true).Foreground(tui.Color("#00fe00"))
		yellow = tui.NewStyle().Bold(true).Foreground(tui.Color("#fede00"))
		red    = tui.NewStyle().Bold(true).Foreground(tui.Color("#fe0000"))
	)
	draw := func(metric *kes.Metric, reqRate float64) {
		fmt.Println(header.Render("\nRequest    OK [2xx]       Err [4xx]       Err [5xx]      Req/s        Latency"))
		fmt.Printf("%s%s%s%s%s\n",
			green.Render(fmt.Sprintf("%19d", metric.RequestOK)),
			yellow.Render(fmt.Sprintf("%16d", metric.RequestErr)),
			red.Render(fmt.Sprintf("%16d", metric.RequestFail)),
			fmt.Sprintf("%11.2f", reqRate),
			fmt.Sprintf("%15s", avgLatency(metric.LatencyHistogram).Round(time.Millisecond)),
		)
		fmt.Printf("%35s%33s%33s\n\n",
			green.Render(fmt.Sprintf("%.2f%%", 100*float64(metric.RequestOK)/float64(metric.RequestN()))),
			yellow.Render(fmt.Sprintf("%.2f%%", 100*float64(metric.RequestErr)/float64(metric.RequestN()))),
			red.Render(fmt.Sprintf("%.2f%%", 100*float64(metric.RequestFail)/float64(metric.RequestN()))),
		)
		fmt.Println(header.Render("System       UpTime            Heap           Stack       CPUs        Threads"))
		fmt.Printf(
			"%19s%16s%16s%11d%15d\n\n",
			metric.UpTime,
			mem.FormatSize(mem.Size(metric.HeapAlloc), 'D', 1),
			mem.FormatSize(mem.Size(metric.StackAlloc), 'D', 1),
			metric.UsableCPUs,
			metric.Threads,
		)
	}
	clearScreen := func() {
		fmt.Print(EraseLine, EraseLine, EraseLine, EraseLine, EraseLine, EraseLine, EraseLine, EraseLine)
	}

	var (
		metric   kes.Metric
		requestN uint64
		reqRate  float64
		drawn    bool
	)
	fmt.Print(HideCursor)
	defer fmt.Print(ShowCursor)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(rate)
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

			if drawn {
				clearScreen()
			}
			draw(&metric, reqRate)
			drawn = true
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	wg.Wait()
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
