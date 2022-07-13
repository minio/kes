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
	"strconv"
	"strings"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	flag "github.com/spf13/pflag"
)

const statusCmdUsage = `Usage:
    kes status [options]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -s, --short              Print status information in a short summary format.
        --api                List all server APIs.
        --json               Print status information in JSON format.
        --color <when>       Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.

    -h, --help               Print command line options.
`

func statusCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, statusCmdUsage) }

	var (
		jsonFlag           bool
		shortFlag          bool
		apiFlag            bool
		colorFlag          colorOption
		insecureSkipVerify bool
	)
	cmd.BoolVar(&jsonFlag, "json", false, "Print status information in JSON format")
	cmd.BoolVar(&apiFlag, "api", false, "List all server APIs")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	cmd.BoolVarP(&shortFlag, "short", "s", false, "Print status information in a short summary format")
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

	var APIs []kes.API
	if apiFlag {
		APIs, err = client.APIs(ctx)
		if err != nil {
			cli.Fatal(err)
		}
	}

	if jsonFlag {
		encoder := json.NewEncoder(os.Stdout)
		if isTerm(os.Stdout) && !shortFlag {
			encoder.SetIndent("", "  ")
		}
		if apiFlag {
			if err = encoder.Encode(APIs); err != nil {
				cli.Fatal(err)
			}
		} else {
			if err = encoder.Encode(status); err != nil {
				cli.Fatal(err)
			}
		}
		return
	}

	faint := tui.NewStyle()
	dotStyle := tui.NewStyle()
	endpointStyle := tui.NewStyle()
	if colorFlag.Colorize() {
		const (
			ColorDot      = tui.Color("#00f700")
			ColorEndpoint = tui.Color("#00afaf")
		)
		faint = faint.Faint(true)
		dotStyle = dotStyle.Foreground(ColorDot).Bold(true)
		endpointStyle = endpointStyle.Foreground(ColorEndpoint).Bold(true)
	}

	fmt.Println(dotStyle.Render("●"), endpointStyle.Render(strings.TrimPrefix(client.Endpoints[0], "https://")))
	if !shortFlag {
		fmt.Println(
			faint.Render(fmt.Sprintf("  %-8s", "Version")),
			status.Version,
		)
		switch {
		case status.UpTime > 24*time.Hour:
			fmt.Println(
				faint.Render(fmt.Sprintf("  %-8s", "Uptime")),
				fmt.Sprintf("%.f days %.f hours", status.UpTime.Hours()/24, math.Mod(status.UpTime.Hours(), 24)),
			)
		case status.UpTime > 1*time.Hour:
			fmt.Println(
				faint.Render(fmt.Sprintf("  %-8s", "Uptime")),
				fmt.Sprintf("%.f hours", status.UpTime.Hours()),
			)
		case status.UpTime > 1*time.Minute:
			fmt.Println(
				faint.Render(fmt.Sprintf("  %-8s", "Uptime")),
				fmt.Sprintf("%.f minutes", status.UpTime.Minutes()),
			)
		default:
			fmt.Println(
				faint.Render(fmt.Sprintf("  %-8s", "Uptime")),
				fmt.Sprintf("%.f seconds", status.UpTime.Seconds()),
			)
		}
		fmt.Println(
			faint.Render(fmt.Sprintf("  %-8s", "Latency")),
			latency.Round(time.Millisecond),
		)
		fmt.Println(
			faint.Render(fmt.Sprintf("  %-8s", "OS")),
			status.OS,
		)
		fmt.Println(
			faint.Render(fmt.Sprintf("  %-8s", "CPUs")),
			strconv.Itoa(status.UsableCPUs),
			status.Arch,
		)
		fmt.Println(faint.Render(fmt.Sprintf("  %-8s", "Memory")))
		fmt.Println(
			faint.Render(fmt.Sprintf("%3s %-6s", "·", "Heap")),
			formatMemory(status.HeapAlloc),
		)
		fmt.Println(
			faint.Render(fmt.Sprintf("%3s %-6s", "·", "Stack")),
			formatMemory(status.StackAlloc),
		)
	}

	if apiFlag {
		header := tui.NewStyle()
		pathStyle := tui.NewStyle()
		if colorFlag.Colorize() {
			header = header.Faint(true).Underline(true).UnderlineSpaces(false)
			pathStyle = pathStyle.Foreground(tui.AdaptiveColor{Light: "#2E42D1", Dark: "#2e8bc0"}).Inline(true)
		}
		fmt.Println()
		fmt.Println(
			" ",
			header.Render(fmt.Sprintf("%-7s", "Method")),
			header.Render(fmt.Sprintf("%-28s", "API")),
			header.Render("Timeout"),
		)

		for _, api := range APIs {
			timeout := "Inf"
			if api.Timeout > 0 {
				timeout = api.Timeout.String()
			}
			fmt.Println(
				" ",
				fmt.Sprintf("%-7s", api.Method),
				pathStyle.Render(fmt.Sprintf("%-28s", api.Path)),
				timeout,
			)
		}
	}
}
