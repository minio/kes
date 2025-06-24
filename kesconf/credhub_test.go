// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf_test

import (
	"flag"
	"testing"

	"github.com/minio/kes/kesconf"
)

var credhubConfigFile = flag.String("credhub.config", "", "Path to a KES config file with CredHub config")

func TestCredHub(t *testing.T) {
	if *credhubConfigFile == "" {
		t.Skip("CredHub tests disabled. Use -credhub.config=<FILE> to enable them")
	}

	config, err := kesconf.ReadFile(*credhubConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := config.KeyStore.(*kesconf.CredHubKeyStore); !ok {
		t.Fatalf("Invalid Keystore: want %T - got %T", config.KeyStore, &kesconf.CredHubKeyStore{})
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	store, err := config.KeyStore.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create", func(t *testing.T) { testCreate(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Get", func(t *testing.T) { testGet(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Status", func(t *testing.T) { testStatus(ctx, store, t) })
}
