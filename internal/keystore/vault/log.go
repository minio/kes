package vault

import (
	"log/slog"
	"net/http"
	"time"
)

type loggingTransport struct {
	http.RoundTripper
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt := lt.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	start := time.Now()
	resp, err := rt.RoundTrip(req)

	// don't log health checks
	if req.URL.Path != "/v1/sys/health" {
		switch {
		case err != nil:
			slog.Debug("HTTP error",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", obfuscateToken(req.Header.Get("X-Vault-Token"))),
				slog.Duration("duration", time.Since(start)),
				slog.String("error", err.Error()))
		case resp.StatusCode >= 300:
			slog.Debug("HTTP error response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", obfuscateToken(req.Header.Get("X-Vault-Token"))),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		default:
			slog.Debug("HTTP success response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", obfuscateToken(req.Header.Get("X-Vault-Token"))),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		}
	}

	return resp, err
}

func obfuscateToken(token string) string {
	switch {
	case len(token) == 0:
		return ""
	case len(token) > 8:
		return "***" + token[len(token)-4:]
	default:
		return "***"
	}
}
