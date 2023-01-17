// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/keserv"
	flag "github.com/spf13/pflag"
)

const migrateCmdUsage = `Usage:
    kes migrate [options] [<pattern>]

Options:
    --from <PATH>            Path to the KES config file of the migration source.
    --to   <PATH>            Path to the KES config file of the migration target.

    -f, --force              Migrate keys even if a key with the same name exists
                             at the target. The existing keys will be deleted.

    --merge                  Merge the source into the target by only migrating
                             those keys that do not exist at the target.

    --color <when>           Specify when to use colored output. The automatic
                             mode only enables colors if an interactive terminal
                             is detected - colors are automatically disabled if
                             the output goes to a pipe.
                             Possible values: *auto*, never, always.

    -h, --help               Print command line options.

Examples:
    $ kes migrate --from vault-config.yml --to aws-config.yml
`

func migrateCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, migrateCmdUsage) }

	var (
		fromPath  string
		toPath    string
		force     bool
		merge     bool
		colorFlag colorOption
	)
	cmd.StringVar(&fromPath, "from", "", "Path to the config file of the migration source")
	cmd.StringVar(&toPath, "to", "", "Path to the config file of the migration target")
	cmd.BoolVarP(&force, "force", "f", false, "Overwrite existing keys at the migration target")
	cmd.BoolVar(&merge, "merge", false, "Only migrate keys that don't exist at the migration target")
	cmd.Var(&colorFlag, "color", "Specify when to use colored output")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes migrate --help'", err)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes migrate --help'")
	}
	if fromPath == "" {
		cli.Fatal("no migration source specified. Use '--from' to specify a config file")
	}
	if toPath == "" {
		cli.Fatal("no migration target specified. Use '--to' to specify a config file")
	}
	if force && merge {
		cli.Fatal("mutually exclusive options '--force' and '--merge' specified")
	}

	pattern := cmd.Arg(0)
	if pattern == "" {
		pattern = "*"
	}

	sourceConfig, err := keserv.ReadServerConfig(fromPath)
	if err != nil {
		cli.Fatalf("failed to read '--from' config file: %v", err)
	}

	targetConfig, err := keserv.ReadServerConfig(toPath)
	if err != nil {
		cli.Fatalf("failed to read '--to' config file: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	src, err := connect(ctx, sourceConfig, nil)
	if err != nil {
		cli.Fatal(err)
	}
	dst, err := connect(ctx, targetConfig, nil)
	if err != nil {
		cli.Fatal(err)
	}

	srcKind, srcEndpoint, err := description(sourceConfig)
	if err != nil {
		cli.Fatal(err)
	}
	dstKind, dstEndpoint, err := description(targetConfig)
	if err != nil {
		cli.Fatal(err)
	}

	kmsStyle := tui.NewStyle()
	if colorFlag.Colorize() {
		kmsStyle = kmsStyle.Bold(true)
	}
	cli.Println("Starting key migration...")
	cli.Println()
	cli.Println(kmsStyle.Render(fmt.Sprintf("Source:   %s %s", srcKind, srcEndpoint)))
	cli.Println(kmsStyle.Render(fmt.Sprintf("Target:   %s %s", dstKind, dstEndpoint)))
	cli.Println()

	if force {
		forceStyle := tui.NewStyle()
		if colorFlag.Colorize() {
			const ColorName tui.Color = "#eed202"
			forceStyle = forceStyle.Foreground(ColorName)
		}
		cli.Println(forceStyle.Render("Warning:"), "Existing keys will be overwritten.")
	}
	if merge {
		mergeStyle := tui.NewStyle()
		if colorFlag.Colorize() {
			const ColorName tui.Color = "#eed202"
			mergeStyle = mergeStyle.Foreground(ColorName)
		}
		cli.Println(mergeStyle.Render("Warning:"), "Only key names that don't exist at the target will be migrated.")
	}

	var N atomic.Uint64
	errChan := make(chan error, 1)
	go func() {
		keys, err := src.List(ctx)
		if err != nil {
			errChan <- err
			return
		}
		defer keys.Close()

		for keys.Next() {
			name := keys.Name()
			if ok, _ := filepath.Match(pattern, name); !ok {
				continue
			}

			key, err := src.Get(ctx, name)
			if err != nil {
				errChan <- fmt.Errorf("failed to migrate %q: %v\nMigrated keys: %d", name, err, N.Load())
				return
			}

			err = dst.Create(ctx, name, key)
			if merge && errors.Is(err, kes.ErrKeyExists) {
				continue // Do not increment the counter since we skip this key
			}
			if force && errors.Is(err, kes.ErrKeyExists) { // Try to overwrite the key
				if err = dst.Delete(ctx, keys.Name()); err != nil {
					errChan <- fmt.Errorf("failed to migrate %q: %v\nMigrated keys: %d", name, err, N.Load())
					return
				}
				err = dst.Create(ctx, keys.Name(), key)
			}
			if err != nil {
				errChan <- fmt.Errorf("failed to migrate %q: %v\nMigrated keys: %d", name, err, N.Load())
				return
			}
			N.Add(1)
		}
		close(errChan)
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	start := time.Now()
	isTerminal := isTerm(os.Stdout)
	for {
		select {
		case t := <-ticker.C:
			if isTerminal {
				cli.Print("\033[2K\r")
			} else {
				cli.Println()
			}
			cli.Printf("Migrated %d keys in %.0fs", N.Load(), t.Sub(start).Seconds())
		case err := <-errChan:
			if isTerminal {
				cli.Print("\033[2K\r")
			} else {
				cli.Println()
			}
			if err != nil {
				cli.Fatal(err)
			}
			doneStyle := tui.NewStyle()
			if colorFlag.Colorize() {
				const ColorName tui.Color = "#008000"
				doneStyle = doneStyle.Foreground(ColorName)
			}
			cli.Println(
				fmt.Sprintf("Migrated %d keys in %.0fs", N.Load(), time.Since(start).Seconds()),
				doneStyle.Render("DONE"),
			)
			return
		case <-ctx.Done():
			return
		}
	}
}
