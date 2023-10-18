// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/minio/kes"
)

// This example shows how to connect an AuditHandler
// to any slog.Handler, here an TextHandler writing
// to stdout.
func ExampleAuditLogHandler() {
	audit := &kes.AuditLogHandler{
		Handler: slog.NewTextHandler(os.Stdout, nil),
	}
	conf := &kes.Config{
		AuditLog: audit,
	}
	_ = conf

	// Handle will be called by the KES server internally
	audit.Handle(context.Background(), kes.AuditRecord{
		Time:         time.Date(2023, time.October, 19, 8, 44, 0, 0, time.UTC),
		Method:       http.MethodPut,
		Path:         "/v1/key/create/my-key",
		Identity:     "2ecb8804e7702a6b768e89b7bba5933044c9d071e4f4035235269b919e56e691",
		RemoteIP:     netip.MustParseAddr("10.1.2.3"),
		StatusCode:   http.StatusOK,
		ResponseTime: 200 * time.Millisecond,
		Level:        slog.LevelInfo,
		Message:      "secret key 'my-key' created",
	})
	// Output:
	// time=2023-10-19T08:44:00.000Z level=INFO msg="secret key 'my-key' created" req.method=PUT req.path=/v1/key/create/my-key req.ip=10.1.2.3 req.identity=2ecb8804e7702a6b768e89b7bba5933044c9d071e4f4035235269b919e56e691 res.code=200 res.time=200ms
}
