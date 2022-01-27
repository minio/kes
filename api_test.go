// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"context"
	"testing"

	"github.com/minio/kes/kestest"
)

func TestClient_CreateKey(t *testing.T) {
	server := kestest.NewServer()
	defer server.Close()

	const KeyName = "my-key"
	if err := server.Client().CreateKey(context.Background(), KeyName); err != nil {
		t.Fatalf("Failed to create key %q: %v", KeyName, err)
	}
}

func TestClient_DeleteKey(t *testing.T) {
	server := kestest.NewServer()
	defer server.Close()

	const KeyName = "my-key"
	if err := server.Client().CreateKey(context.Background(), KeyName); err != nil {
		t.Fatalf("Failed to create key %q: %v", KeyName, err)
	}

	if err := server.Client().DeleteKey(context.Background(), KeyName); err != nil {
		t.Fatalf("Failed to delete key %q: %v", KeyName, err)
	}
}
