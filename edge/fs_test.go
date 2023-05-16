// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge_test

import (
	"flag"
	"testing"

	"github.com/minio/kes/edge"
)

var FSPath = flag.String("fs.path", "", "Path used for FS tests")

func TestFS(t *testing.T) {
	if *FSPath == "" {
		t.Skip("FS tests disabled. Use -fs.path=<path> to enable them")
	}
	config := edge.FSKeyStore{
		Path: *FSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	store, err := config.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create", func(t *testing.T) { testCreate(ctx, store, t) })
	t.Run("Set", func(t *testing.T) { testSet(ctx, store, t) })
	t.Run("Get", func(t *testing.T) { testGet(ctx, store, t) })
	t.Run("Status", func(t *testing.T) { testStatus(ctx, store, t) })
}
