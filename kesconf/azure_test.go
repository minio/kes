// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf

import (
	"flag"
	"os"
	"testing"
)

var azureConfigFile = flag.String("azure.config", "", "Path to a KES config file with Azure KeyVault config")

func TestAzure(t *testing.T) {
	if *azureConfigFile == "" {
		t.Skip("Azure KeyVault tests disabled. Use -azure.config=<FILE> to enable them")
	}
	file, err := os.Open(*azureConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	config, err := ReadFile(*azureConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := config.KeyStore.(*AzureKeyVaultKeyStore); !ok {
		t.Fatalf("Invalid Keystore: want %T - got %T", config.KeyStore, &AzureKeyVaultKeyStore{})
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
