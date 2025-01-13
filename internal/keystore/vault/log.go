package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
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
		auth := obfuscateToken(req.Header.Get(vaultapi.AuthHeaderName))
		switch {
		case err != nil:
			slog.Debug("HTTP error",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", auth),
				slog.Duration("duration", time.Since(start)),
				slog.String("error", err.Error()))
		case resp.StatusCode >= 300:
			slog.Debug("HTTP error response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", auth),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		default:
			slog.Debug("HTTP success response",
				slog.String("method", req.Method),
				slog.String("url", req.URL.String()),
				slog.String("auth", auth),
				slog.Duration("duration", time.Since(start)),
				slog.String("status", resp.Status))
		}
	}

	return resp, err
}

func obfuscateToken(token string) string {
	if len(token) == 0 {
		return ""
	}
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%s (hashed)", hex.EncodeToString(hash[:16]))
}
