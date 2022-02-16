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

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/yml"
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

	sourceConfig, err := yml.ReadServerConfig(fromPath)
	if err != nil {
		cli.Fatalf("failed to read '--from' config file: %v", err)
	}

	targetConfig, err := yml.ReadServerConfig(toPath)
	if err != nil {
		cli.Fatalf("failed to read '--to' config file: %v", err)
	}

	src, err := connect(sourceConfig, quiet, nil)
	if err != nil {
		cli.Fatal(err)
	}
	dst, err := connect(targetConfig, quiet, nil)
	if err != nil {
		cli.Fatal(err)
	}

	var (
		n           uint64
		uiTicker    = time.NewTicker(100 * time.Millisecond)
		ctx, cancel = signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	)
	defer cancel()
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
	if err = iterator.Err(); err != nil {
		quiet.ClearLine()
		cli.Fatalf("failed to list keys: %v\nMigrated keys: %d", err, atomic.LoadUint64(&n))
	}
	cancel()

	// At the end we show how many keys we have migrated successfully.
	msg := fmt.Sprintf("Migrated keys: %d ", atomic.LoadUint64(&n))
	quiet.ClearMessage(msg)
	quiet.Println(msg)
}
