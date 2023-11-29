// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf

import (
	"flag"
	"testing"
)

var vaultCfgFile = flag.String("vault-ci.config", "", "Path to a KES config file with Hashicorp Vault config")

func TestVaultCI(t *testing.T) {
	if *vaultCfgFile == "" {
		t.Skip("Vault tests disabled. Use -vault-ci.config=<FILE> to enable them")
	}

	config, err := ReadFile(*vaultCfgFile)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := config.KeyStore.(*VaultKeyStore); !ok {
		t.Fatalf("Invalid Keystore: want %T - got %T", config.KeyStore, &VaultKeyStore{})
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
