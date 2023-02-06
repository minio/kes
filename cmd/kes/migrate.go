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

	"github.com/fatih/color"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/keserv"
	flag "github.com/spf13/pflag"
	"golang.org/x/term"
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

    -q, --quiet              Do not print progress information.
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
		quietFlag bool
	)
	cmd.StringVar(&fromPath, "from", "", "Path to the config file of the migration source")
	cmd.StringVar(&toPath, "to", "", "Path to the config file of the migration target")
	cmd.BoolVarP(&force, "force", "f", false, "Overwrite existing keys at the migration target")
	cmd.BoolVar(&merge, "merge", false, "Only migrate keys that don't exist at the migration target")
	cmd.BoolVarP(&quietFlag, "quiet", "q", false, "Do not print progress information")
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

	quiet := quiet(quietFlag)
	pattern := cmd.Arg(0)
	if pattern == "" {
		pattern = "*"
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	sourceConfig, err := keserv.ReadServerConfig(fromPath)
	if err != nil {
		cli.Fatalf("failed to read '--from' config file: %v", err)
	}

	targetConfig, err := keserv.ReadServerConfig(toPath)
	if err != nil {
		cli.Fatalf("failed to read '--to' config file: %v", err)
	}

	src, err := sourceConfig.KMS.Connect(ctx)
	if err != nil {
		cli.Fatal(err)
	}
	dst, err := targetConfig.KMS.Connect(ctx)
	if err != nil {
		cli.Fatal(err)
	}

	var (
		n        uint64
		uiTicker = time.NewTicker(100 * time.Millisecond)
	)
	defer uiTicker.Stop()

	// Now, we start listing the keys at the source.
	iterator, err := src.List(ctx)
	if err != nil {
		cli.Fatal(err)
	}

	// Then, we start the UI which prints how many keys have
	// been migrated in fixed time intervals.
	go func() {
		for {
			select {
			case <-uiTicker.C:
				msg := fmt.Sprintf("Migrated keys: %d", atomic.LoadUint64(&n))
				quiet.ClearMessage(msg)
				quiet.Print(msg)
			case <-ctx.Done():
				return
			}
		}
	}()

	// Finally, we start the actual migration.
	for iterator.Next() {
		name := iterator.Name()
		if ok, _ := filepath.Match(pattern, name); !ok {
			continue
		}

		key, err := src.Get(ctx, name)
		if err != nil {
			quiet.ClearLine()
			cli.Fatalf("failed to migrate %q: %v\nMigrated keys: %d", name, err, atomic.LoadUint64(&n))
		}

		err = dst.Create(ctx, name, key)
		if merge && errors.Is(err, kes.ErrKeyExists) {
			continue // Do not increment the counter since we skip this key
		}
		if force && errors.Is(err, kes.ErrKeyExists) { // Try to overwrite the key
			if err = dst.Delete(ctx, name); err != nil {
				quiet.ClearLine()
				cli.Fatalf("failed to migrate %q: %v\nMigrated keys: %d", name, err, atomic.LoadUint64(&n))
			}
			err = dst.Create(ctx, name, key)
		}
		if err != nil {
			quiet.ClearLine()
			cli.Fatalf("failed to migrate %q: %v\nMigrated keys: %d", name, err, atomic.LoadUint64(&n))
		}
		atomic.AddUint64(&n, 1)
	}
	if err = iterator.Close(); err != nil {
		quiet.ClearLine()
		cli.Fatalf("failed to list keys: %v\nMigrated keys: %d", err, atomic.LoadUint64(&n))
	}
	cancel()

	// At the end we show how many keys we have migrated successfully.
	msg := fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n))
	quiet.ClearMessage(msg)
	quiet.Println(msg)
}

// quiet is a boolean flag.Value that can print
// to STDOUT.
//
// If quiet is set to true then all quiet.Print*
// calls become no-ops and no output is printed to
// STDOUT.
type quiet bool

// Print behaves as fmt.Print if quiet is false.
// Otherwise, Print does nothing.
func (q quiet) Print(a ...any) {
	if !q {
		fmt.Print(a...)
	}
}

// Printf behaves as fmt.Printf if quiet is false.
// Otherwise, Printf does nothing.
func (q quiet) Printf(format string, a ...any) {
	if !q {
		fmt.Printf(format, a...)
	}
}

// Println behaves as fmt.Println if quiet is false.
// Otherwise, Println does nothing.
func (q quiet) Println(a ...any) {
	if !q {
		fmt.Println(a...)
	}
}

// ClearLine clears the last line written to STDOUT if
// STDOUT is a terminal that supports terminal control
// sequences.
//
// Otherwise, ClearLine just prints a empty newline.
func (q quiet) ClearLine() {
	if color.NoColor {
		q.Println()
	} else {
		q.Print(eraseLine)
	}
}

const (
	eraseLine = "\033[2K\r"
	moveUp    = "\033[1A"
)

// ClearMessage tries to erase the given message from STDOUT
// if STDOUT is a terminal that supports terminal control sequences.
//
// Otherwise, ClearMessage just prints an empty newline.
func (q quiet) ClearMessage(msg string) {
	if color.NoColor {
		q.Println()
		return
	}

	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil { // If we cannot get the width, just erasure one line
		q.Print(eraseLine)
		return
	}

	// Erase and move up one line as long as the message is not empty.
	for len(msg) > 0 {
		q.Print(eraseLine)

		if len(msg) < width {
			break
		}
		q.Print(moveUp)
		msg = msg[width:]
	}
}
