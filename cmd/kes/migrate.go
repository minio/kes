// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/kesconf"
	"github.com/minio/kms-go/kes"
	"github.com/minio/kms-go/kms"
	flag "github.com/spf13/pflag"
)

const migrateUsage = `Usage:
    kes migrate [-f] [--merge] [--from FILE] [--to FILE] [PATTERN]
    kes migrate [-k] [-f] [--merge] [--from FILE] [--s HOST] [-e ENCLAVE]
                [-a KEY] [PATTERN]

Options:
    --from <PATH>            Path to source KES config file.
    --to   <PATH>            Path to target KES config file.

    -s, --server HOST        KMS server endpoint to which keys are migrated.
                             Defaults to the value of $MINIO_KMS_SERVER
    -e, --enclave ENCLAVE    KMS enclave endpoint to which keys are migrated.
                             Defaults to the value of $MINIO_KMS_ENCLAVE
    -a, --api-key KEY        KMS API key used to authenticate to the KMS server.
                             Defaults to the value of $MINIO_KMS_API_KEY
    -k, --insecure           Skip KMS server certificate verification.

    -f, --force              Migrate keys even if a key with the same name exists
                             at the target. The existing keys will be deleted.

    --merge                  Merge the source into the target by only migrating
                             those keys that do not exist at the target.
`

func migrate(args []string) {
	var (
		insecureSkipVerify bool
		force              bool
		merge              bool
		fromPath           string
		toPath             string
		kmsServer          string
		kmsEnclave         string
		kmsAPIKey          string
	)

	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, migrateUsage) }

	flags.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "")
	flags.BoolVarP(&force, "force", "f", false, "")
	flags.BoolVar(&merge, "merge", false, "")
	flags.StringVar(&fromPath, "from", "", "")
	flags.StringVar(&toPath, "to", "", "")
	flags.StringVarP(&kmsServer, "server", "s", cli.Env("MINIO_KMS_SERVER"), "")
	flags.StringVarP(&kmsEnclave, "enclave", "e", cli.Env("MINIO_KMS_ENCLAVE"), "")
	flags.StringVarP(&kmsAPIKey, "api-key", "a", cli.Env("MINIO_KMS_API_KEY"), "")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes migrate --help'", err)
	}

	cli.Assert(flags.NArg() <= 1, "too many arguments")
	cli.Assert(fromPath != "", "no source specified. Use '--from' flag")
	if flags.Changed("server") {
		cli.Assert(toPath == "", "cannot use '-s / --server' and '--to' flag")
	}
	if flags.Changed("enclave") {
		cli.Assert(toPath == "", "cannot use '-e / --enclave' and '--to' flag")
	}
	if flags.Changed("api-key") {
		cli.Assert(toPath == "", "cannot use '-a / --api-key' and '--to' flag")
	}
	if toPath != "" {
		cli.Assert(!insecureSkipVerify, "cannot use '-k / --insecure' and '--to' flag")
	}
	if toPath == "" {
		cli.Assert(kmsServer != "", "missing migration target. Use '--to' or '--server'")
		cli.Assert(kmsEnclave != "", "no KMS enclave specified. Use '--enclave'")
		cli.Assert(kmsAPIKey != "", "no KMS API key specified. Use '--api-key'")
	}
	cli.Assert(!(force && merge), "'--force' and '--merge' flags are mutually exclusive")

	pattern := flags.Arg(0)
	if pattern == "" {
		pattern = "*"
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	srcConf, err := kesconf.ReadFile(fromPath)
	cli.Assert(err == nil, err)

	src, err := srcConf.KeyStore.Connect(ctx)
	cli.Assert(err == nil, err)

	iter := &kes.ListIter[string]{
		NextFunc: src.List,
	}

	// Migrate from one KES backend (--from) to another one (--to).
	if toPath != "" {
		dstConf, err := kesconf.ReadFile(toPath)
		cli.Assert(err == nil, err)

		dst, err := dstConf.KeyStore.Connect(ctx)
		cli.Assert(err == nil, err)

		var (
			count  atomic.Uint64
			ticker = time.NewTicker(1 * time.Second)
		)
		fmt.Println("Starting key migration:")
		fmt.Println()
		go func() {
			for {
				select {
				case <-ticker.C:
					if n := count.Load(); n <= 1 {
						fmt.Printf("Migrated %6d key  ...\n", n)
					} else {
						fmt.Printf("Migrated %6d keys ...\n", n)
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		for {
			name, err := iter.Next(ctx)
			if err == io.EOF {
				break
			}
			cli.Assert(err == nil, err)

			if ok, _ := filepath.Match(pattern, name); !ok {
				continue
			}

			key, err := src.Get(ctx, name)
			cli.Assert(err == nil, err)

			err = dst.Create(ctx, name, key)
			if merge && errors.Is(err, kes.ErrKeyExists) {
				continue // Do not increment the counter since we skip this key
			}
			if force && errors.Is(err, kes.ErrKeyExists) { // Try to overwrite the key
				if err = dst.Delete(ctx, name); err != nil {
					cli.Assert(err == nil, err)
				}
				err = dst.Create(ctx, name, key)
			}
			cli.Assert(err == nil, err)
			count.Add(1)
		}
		ticker.Stop()

		if n := count.Load(); n == 0 {
			fmt.Println("Migration succeeded! No keys migrated.")
		} else {
			fmt.Printf("Migrated %6d keys successfully!\n", count.Load())
		}
		return
	}

	// Migrate from a KES backend (--from) to a KMS server (-s / --server).
	apiKey, err := kms.ParseAPIKey(kmsAPIKey)
	cli.Assert(err == nil, err)

	client, err := kms.NewClient(&kms.Config{
		Endpoints: []string{kmsServer},
		APIKey:    apiKey,
		TLS: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	})
	cli.Assert(err == nil, err)

	var (
		count  atomic.Uint64
		ticker = time.NewTicker(1 * time.Second)
	)
	fmt.Println("Starting key migration:")
	fmt.Println()
	go func() {
		for {
			select {
			case <-ticker.C:
				if n := count.Load(); n <= 1 {
					fmt.Printf("Migrated %6d key  ...\n", n)
				} else {
					fmt.Printf("Migrated %6d keys ...\n", n)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		name, err := iter.Next(ctx)
		if err == io.EOF {
			break
		}
		cli.Assert(err == nil, err)

		if ok, _ := filepath.Match(pattern, name); !ok {
			continue
		}

		b, err := src.Get(ctx, name)
		cli.Assert(err == nil, err)

		key, err := crypto.ParseKeyVersion(b)
		cli.Assert(err == nil, err)

		err = client.ImportKey(ctx, &kms.ImportKeyRequest{
			Enclave: kmsEnclave,
			Name:    name,
			Type:    kms.SecretKeyType(key.Key.Type()),
			Key:     key.Key.Bytes(),
		})
		if merge && errors.Is(err, kms.ErrKeyExists) {
			continue // Do not increment the counter since we skip this key
		}
		if force && errors.Is(err, kms.ErrKeyExists) { // Try to overwrite the key
			if err = client.DeleteKey(ctx, &kms.DeleteKeyRequest{Enclave: kmsEnclave, Name: name, AllVersions: true}); err != nil {
				cli.Assert(err == nil, err)
			}
			err = client.ImportKey(ctx, &kms.ImportKeyRequest{
				Enclave: kmsEnclave,
				Name:    name,
				Type:    kms.SecretKeyType(key.Key.Type()),
				Key:     key.Key.Bytes(),
				// TODO(aead): migrate HMAC key as well
			})
		}
		cli.Assert(err == nil, err)
		count.Add(1)
	}
	ticker.Stop()

	if n := count.Load(); n == 0 {
		fmt.Println("Migration succeeded! No keys migrated.")
	} else {
		fmt.Printf("Migrated %6d keys successfully!\n", count.Load())
	}
}
