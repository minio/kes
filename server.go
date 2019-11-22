package key

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/aead/key/internal/xhttp"
	"github.com/aead/key/kms"
)

// A Server defines parameters for running a key server.
type Server struct {
	Addr string

	TLSConfig *tls.Config

	KeyStore kms.KeyStore

	Roles *Roles

	ErrorLog *log.Logger
}

// ServeTCP listens on the TCP network address srv.Addr and
// than handles requests on incoming TLS connections. If
// srv.Addr is blank, ":https" is used. Accepted connections
// are configured to enable TCP keep-alives.
//
// The TLS certificate must be populated via
// Server.TLSConfig.Certificates or Server.TLSConfig.GetCertificate.
//
// The Server closes itself when <-ctx.Done() returns by first
// trying a graceful shutdown. If the graceful shutdown takes
// longer than timeout, ServeTCP immediately closes the Server
// by calling http.Server.Close().
//
// ServeTCP returns either any error encountered when creating
// the TCP socket, handling a TCP connection or any error
// encountered while closing the Server. It always returns a
// non-nil error.
func (srv *Server) ServeTCP(ctx context.Context, timeout time.Duration) error {
	if srv.KeyStore == nil {
		return errors.New("key: no key store specified")
	}
	if srv.Roles == nil {
		return errors.New("key: no roles specified")
	}
	server := http.Server{
		Addr:      srv.Addr,
		Handler:   newServerMux(srv.KeyStore, srv.Roles),
		TLSConfig: srv.TLSConfig.Clone(),
		ErrorLog:  srv.ErrorLog,
	}

	serveErr := make(chan error)
	go func() { serveErr <- server.ListenAndServeTLS("", "") }()
	select {
	case <-ctx.Done():
		shutdownCtxt, _ := context.WithDeadline(context.Background(), time.Now().Add(timeout))
		if err := server.Shutdown(shutdownCtxt); err != nil {
			if err == context.DeadlineExceeded {
				return server.Close()
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return http.ErrServerClosed
	case err := <-serveErr:
		return err
	}
}

func newServerMux(store kms.KeyStore, roles *Roles) http.Handler {
	const maxBody = 1 << 20
	mux := http.NewServeMux()

	mux.Handle("/v1/key/create", xhttp.NotFound)
	mux.Handle("/v1/key/create/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		roles.Enforce,
		createKeyHandler(store),
	})
	mux.Handle("/v1/key/delete", xhttp.NotFound)
	mux.Handle("/v1/key/delete/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		deleteKeyHandler(store),
	})
	mux.Handle("/v1/key/generate", xhttp.NotFound)
	mux.Handle("/v1/key/generate/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		roles.Enforce,
		generateKeyHandler(store),
	})
	mux.Handle("/v1/key/decrypt", xhttp.NotFound)
	mux.Handle("/v1/key/decrypt/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		roles.Enforce,
		decryptKeyHandler(store),
	})

	mux.Handle("/v1/policy/write", xhttp.NotFound)
	mux.Handle("/v1/policy/write/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		roles.Enforce,
		writePolicyHandler(roles),
	})
	mux.Handle("/v1/policy/read", xhttp.NotFound)
	mux.Handle("/v1/policy/read/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		readPolicyHandler(roles),
	})
	mux.Handle("/v1/policy/list", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		listPoliciesHandler(roles),
	})
	mux.Handle("/v1/policy/delete", xhttp.NotFound)
	mux.Handle("/v1/policy/delete/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		deletePolicyHandler(roles),
	})

	mux.Handle("/v1/identity/assign", xhttp.NotFound)
	mux.Handle("/v1/identity/assign/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		roles.Enforce,
		assignIdentityHandler(roles),
	})
	mux.Handle("/v1/identity/list/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		listIdentitiesHandler(roles),
	})
	mux.Handle("/v1/identity/forget", xhttp.NotFound)
	mux.Handle("/v1/identity/forget/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		roles.Enforce,
		forgetIdentityHandler(roles),
	})
	return mux
}
