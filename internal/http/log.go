package http

import (
	"log/slog"
	"net/http"
	"slices"
	"time"
)

// LoggingTransport is an http.RoundTripper that logs the request and response.
type LoggingTransport struct {
	http.RoundTripper
	skipPaths []string
}

// NewLoggingTransport creates an http.RoundTripper that logs the request and response.
func NewLoggingTransport(rt http.RoundTripper, skipPaths ...string) *LoggingTransport {
	return &LoggingTransport{
		RoundTripper: rt,
		skipPaths:    skipPaths,
	}
}

// RoundTrip implements the RoundTripper interface.
func (lt *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := lt.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	start := time.Now()
	resp, err := rt.RoundTrip(req)

	// don't log health checks
	if !slices.Contains(lt.skipPaths, req.URL.Path) {
		switch {
		case err != nil:
			slog.Info("HTTP error",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.Duration("duration", time.Since(start)),
				slog.String("error", err.Error()))
		case resp.StatusCode >= 300:
			slog.Info("HTTP error response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		default:
			slog.Debug("HTTP success response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		}
	}

	return resp, err
}
