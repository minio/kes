// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf_test

import (
	"flag"
	"testing"

	"github.com/minio/kes/kesconf"
)

var FSPath = flag.String("fs.path", "", "Path used for FS tests")

func TestFS(t *testing.T) {
	if *FSPath == "" {
		t.Skip("FS tests disabled. Use -fs.path=<path> to enable them")
	}
	config := kesconf.FSKeyStore{
		Path: *FSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	store, err := config.Connect(ctx, false)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create", func(t *testing.T) { testCreate(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Get", func(t *testing.T) { testGet(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Status", func(t *testing.T) { testStatus(ctx, store, t) })
}
