// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf

import (
	"flag"
	"testing"
)

var keyControlConfigFile = flag.String("entrust.config", "", "Path to a KES config file with Entrust KeyControl config")

func TestKeyControl(t *testing.T) {
	if *keyControlConfigFile == "" {
		t.Skip("KeyControl tests disabled. Use -entrust.config=<FILE> to enable them")
	}

	config, err := ReadFile(*keyControlConfigFile)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := config.KeyStore.(*EntrustKeyControlKeyStore); !ok {
		t.Fatalf("Invalid Keystore: want %T - got %T", config.KeyStore, &EntrustKeyControlKeyStore{})
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
