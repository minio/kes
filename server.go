package key

import (
	"crypto/tls"
	"net"
	"net/http"

	"github.com/aead/key/internal/xhttp"
	"github.com/aead/key/kms"
)

type Server struct {
	Addr string

	TLSConfig *tls.Config

	KeyStore kms.KeyStore

	Roles Roles
}

func (s *Server) ListenAndServe(certFile, keyFile string) error {
	const maxBody = 1 << 20
	mux := http.NewServeMux()

	mux.Handle("/v1/key/create", xhttp.NotFound)
	mux.Handle("/v1/key/create/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		s.Roles.Enforce,
		createKeyHandler(s.KeyStore),
	})
	mux.Handle("/v1/key/delete", xhttp.NotFound)
	mux.Handle("/v1/key/delete/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		deleteKeyHandler(s.KeyStore),
	})
	mux.Handle("/v1/key/generate", xhttp.NotFound)
	mux.Handle("/v1/key/generate/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		s.Roles.Enforce,
		generateKeyHandler(s.KeyStore),
	})
	mux.Handle("/v1/key/decrypt", xhttp.NotFound)
	mux.Handle("/v1/key/decrypt/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		s.Roles.Enforce,
		decryptKeyHandler(s.KeyStore),
	})

	mux.Handle("/v1/policy/write", xhttp.NotFound)
	mux.Handle("/v1/policy/write/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		s.Roles.Enforce,
		writePolicyHandler(&s.Roles),
	})
	mux.Handle("/v1/policy/read", xhttp.NotFound)
	mux.Handle("/v1/policy/read/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		readPolicyHandler(&s.Roles),
	})
	mux.Handle("/v1/policy/list", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		listPoliciesHandler(&s.Roles),
	})
	mux.Handle("/v1/policy/delete", xhttp.NotFound)
	mux.Handle("/v1/policy/delete/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		deletePolicyHandler(&s.Roles),
	})

	mux.Handle("/v1/identity/assign", xhttp.NotFound)
	mux.Handle("/v1/identity/assign/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodPost),
		xhttp.LimitRequestBody(maxBody),
		s.Roles.Enforce,
		assignIdentityHandler(&s.Roles),
	})
	mux.Handle("/v1/identity/list/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodGet),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		listIdentitiesHandler(&s.Roles),
	})
	mux.Handle("/v1/identity/forget", xhttp.NotFound)
	mux.Handle("/v1/identity/forget/", xhttp.MultiHandler{
		xhttp.RequireMethod(http.MethodDelete),
		xhttp.LimitRequestBody(0),
		s.Roles.Enforce,
		forgetIdentityHandler(&s.Roles),
	})

	server := http.Server{
		Addr:      s.Addr,
		Handler:   mux,
		TLSConfig: s.TLSConfig.Clone(),
	}
	return server.ListenAndServeTLS(certFile, keyFile)
}

func (s *Server) Serve(l net.Listener, certFile, keyFile string) error {

	server := http.Server{
		Addr: s.Addr,
	}
	return server.ServeTLS(l, certFile, keyFile)
}
