// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/api"
)

// AuditRecord describes an audit event logged by a KES server.
type AuditRecord struct {
	// Point in time when the audit event happened.
	Time time.Time

	// The request HTTP method. (GET, PUT, ...)
	Method string

	// Request URL path. Always starts with a '/'.
	Path string

	// Identity that send the request.
	Identity kes.Identity

	// IP address of the client that sent the request.
	RemoteIP netip.Addr

	// Status code the KES server responded with.
	StatusCode int

	// Amount of time the server took to process the
	// request and generate a response.
	ResponseTime time.Duration

	// The log level of this event.
	Level slog.Level

	// The log message describing the event.
	Message string
}

// An AuditHandler handles audit records produced by a Server.
//
// A typical handler may print audit records to standard error,
// or write them to a file or database.
//
// Any of the AuditHandler's methods may be called concurrently
// with itself or with other methods. It is the responsibility
// of the Handler to manage this concurrency.
type AuditHandler interface {
	// Enabled reports whether the handler handles records at
	// the given level. The handler ignores records whose level
	// is lower. It is called early, before an audit record is
	// created, to safe effort if the audit event should be
	// discarded.
	//
	// The Server will pass the request context as the first
	// argument, or context.Background() if no context is
	// available. Enabled may use the context to make a
	// decision.
	Enabled(context.Context, slog.Level) bool

	// Handle handles the AuditRecord. It will only be called when
	// Enabled returns true.
	//
	// The context is present for providing AuditHandlers access
	// to the context's values and to potentially pass it to an
	// underlying slog.Handler. Canceling the context should not
	// affect record processing.
	Handle(context.Context, AuditRecord) error
}

// AuditLogHandler is an AuditHandler adapter that wraps
// an slog.Handler. It converts AuditRecords to slog.Records
// and passes them to the slog.Handler. An AuditLogHandler
// acts as a bridge between AuditHandlers and slog.Handlers.
type AuditLogHandler struct {
	Handler slog.Handler
}

// Enabled reports whether the AuditLogHandler handles records
// at the given level. It returns true if the underlying handler
// returns true.
func (a *AuditLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return a.Handler.Enabled(ctx, level)
}

// Handle converts the AuditRecord to an slog.Record and
// passes it to the underlying handler.
func (a *AuditLogHandler) Handle(ctx context.Context, r AuditRecord) error {
	rec := slog.Record{
		Time:    r.Time,
		Message: r.Message,
		Level:   r.Level,
	}
	rec.AddAttrs(
		slog.Attr{Key: "req", Value: slog.GroupValue(
			slog.String("method", r.Method),
			slog.String("path", r.Path),
			slog.String("ip", r.RemoteIP.String()),
			slog.String("identity", r.Identity.String()),
		)},
		slog.Attr{Key: "res", Value: slog.GroupValue(
			slog.Int("code", r.StatusCode),
			slog.Duration("time", r.ResponseTime),
		)},
	)
	return a.Handler.Handle(ctx, rec)
}

// An auditLogger records information about a request/response
// handled by the Server.
//
// For each call of its Log method, it creates an AuditRecord and
// passes it to its AuditHandler. If clients have subscribed to
// the AuditLog API, the logger also sends the AuditRecord to these
// clients.
type auditLogger struct {
	h     AuditHandler
	level slog.Leveler

	out *api.Multicast // clients subscribed to the AuditLog API
}

// newAuditLogger returns a new auditLogger passing AuditRecords to h.
// A record is only sent to clients subscribed to the AuditLog API if
// its log level is >= level.
func newAuditLogger(h AuditHandler, level slog.Leveler) *auditLogger {
	return &auditLogger{
		h:     h,
		level: level,
		out:   &api.Multicast{},
	}
}

// Log emits an audit record with the current time, log message,
// response status code and request information.
func (a *auditLogger) Log(msg string, statusCode int, req *api.Request) {
	const Level = slog.LevelInfo
	if Level < a.level.Level() {
		return
	}

	hEnabled, oEnabled := a.h.Enabled(req.Context(), Level), a.out.Num() > 0
	if !hEnabled && !oEnabled {
		return
	}

	now := time.Now()
	remoteIP, _ := netip.ParseAddrPort(req.RemoteAddr)
	r := AuditRecord{
		Time:         time.Now(),
		Method:       req.Method,
		Path:         req.URL.Path,
		Identity:     req.Identity,
		RemoteIP:     remoteIP.Addr(),
		StatusCode:   statusCode,
		ResponseTime: now.Sub(req.Received),
		Level:        Level,
		Message:      msg,
	}
	if hEnabled {
		a.h.Handle(req.Context(), r)
	}

	if !oEnabled {
		return
	}
	json.NewEncoder(a.out).Encode(api.AuditLogEvent{
		Time: r.Time,
		Request: api.AuditLogRequest{
			IP:       r.RemoteIP.String(),
			APIPath:  r.Path,
			Identity: r.Identity.String(),
		},
		Response: api.AuditLogResponse{
			StatusCode: r.StatusCode,
			Time:       r.ResponseTime.Milliseconds(),
		},
	})
}
