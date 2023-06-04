// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edgeconf_test

import (
	"flag"
	"os"
	"testing"

	"github.com/minio/kes/edge/edgeconf"
	"github.com/minio/kes/internal/keystore/fortanix"
)

var fortanixConfigFile = flag.String("fortanix.config", "", "Path to a KES config file with Fortanix SDKMS config")

func TestFortanix(t *testing.T) {
	if *fortanixConfigFile == "" {
		t.Skip("Fortanix tests disabled. Use -fortanix.config=<FILE> to enable them")
	}
	file, err := os.Open(*fortanixConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	ctx, cancel := testingContext(t)
	defer cancel()

	store, _, err := edgeconf.Connect(ctx, file)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := store.(*fortanix.Store); !ok {
		t.Fatalf("Invalid Keystore: want %T - got %T", store, &fortanix.Store{})
	}

	t.Run("Create", func(t *testing.T) { testCreate(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Get", func(t *testing.T) { testGet(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Status", func(t *testing.T) { testStatus(ctx, store, t) })
}
