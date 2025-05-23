// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"io"
	"log/slog"

	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/log"
)

// logHandler is an slog.Handler that handles Server log records.
//
// It wraps a custom slog.Handlers provided by Config.ErrorLog. If
// Config.ErrorLog is nil, a slog.TextHandler to os.Stderr is used
// as default.
//
// Log records may be handled twice. First, they are passed to the
// custom/default handler. For example to write to standard error.
// Second, they are sent to clients, that have subscribed to the
// ErrorLog API, if any.
type logHandler struct {
	h     slog.Handler
	level slog.Leveler

	text slog.Handler
	out  *api.Multicast // clients subscribed to the ErrorLog API
}

// newLogHandler returns a new logHandler that passing records to h.
//
// A record is only sent to clients subscribed to the ErrorLog API if
// its log level is >= level.
func newLogHandler(h slog.Handler, level slog.Leveler) *logHandler {
	handler := &logHandler{
		h:     h,
		level: level,
		out:   &api.Multicast{},
	}
	handler.text = slog.NewTextHandler(handler.out, &slog.HandlerOptions{
		Level: level,
	})
	return handler
}

// newFormattedLogHandler returns a new text or JSON formatted log handler.
func newFormattedLogHandler(w io.Writer, f log.Format, opts *slog.HandlerOptions) slog.Handler {
	switch f {
	case log.JSONFormat:
		return slog.NewJSONHandler(w, opts)
	default:
		return slog.NewTextHandler(w, opts)
	}
}

// Enabled reports whether h handles records at the given level.
func (h *logHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= h.level.Level() && h.h.Enabled(ctx, level) ||
		(h.text.Enabled(ctx, level) && h.out.Num() > 0)
}

// Handle handles r by passing it first to the custom/default handler and
// then sending it to all clients subscribed to the ErrorLog API.
func (h *logHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if r.Level >= h.level.Level() {
		err = h.h.Handle(ctx, r)
	}
	if h.out.Num() > 0 && h.text.Enabled(ctx, r.Level) {
		if tErr := h.text.Handle(ctx, r); err == nil {
			err = tErr
		}
	}
	return err
}

// WithAttrs returns a new Handler whose attributes consist of
// both the receiver's attributes and the arguments.
// The Handler owns the slice: it may retain, modify or discard it.
func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logHandler{
		h:    h.h.WithAttrs(attrs),
		text: h.text.WithAttrs(attrs),
		out:  h.out, // Share all connections to clients
	}
}

// WithGroup returns a new Handler with the given group appended to
// the receiver's existing groups.
func (h *logHandler) WithGroup(name string) slog.Handler {
	return &logHandler{
		h:    h.h.WithGroup(name),
		text: h.text.WithGroup(name),
		out:  h.out, // Share all connections to clients
	}
}

// Handler returns the underlying custom/default slog.Handler.
func (h *logHandler) Handler() slog.Handler { return h.h }
