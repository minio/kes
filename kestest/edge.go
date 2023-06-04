package kestest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"sync"

	kessrv "github.com/minio/kes"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/internal/crypto/fips"
	"github.com/minio/kes/internal/keystore/mem"
)

const (
	DefaultAPIKey = "kes:v1:AD9E7FSYWrMD+VjhI6q545cYT9YOyFxZb7UnjEepYDRc"
	DefaultAdmin  = "3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22"
)

func NewEdgeServer(store edge.KeyStore) *EdgeServer {
	s := &EdgeServer{}
	s.Start(store)
	return s
}

type EdgeServer struct {
	store edge.KeyStore

	srv    *edge.Server
	client *kes.Client

	srvCert    tls.Certificate
	rootCAs    *x509.CertPool
	policies   map[string]*kes.Policy
	identities map[kes.Identity]string

	stop context.CancelFunc
}

func (s *EdgeServer) URL() string {
	return s.srv.State().Addr.URL().String()
}

func (s *EdgeServer) Client() *kes.Client {
	s.client.Endpoints = []string{s.URL()}
	return s.client
}

func (s *EdgeServer) CAs() *x509.CertPool { return s.rootCAs }

func (s *EdgeServer) AddPolicy(name string, policy *kes.Policy, identities ...kes.Identity) {
	if s.policies == nil {
		s.policies = make(map[string]*kes.Policy)
	}
	s.policies[name] = policy

	if len(identities) > 0 {
		if s.identities == nil {
			s.identities = make(map[kes.Identity]string, len(identities))
		}
		for _, id := range identities {
			s.identities[id] = name
		}
	}
	if s.srv != nil {
		s.srv.Update(s.store, &edge.Config{
			TLS: &tls.Config{
				Certificates: []tls.Certificate{s.srvCert},
				ClientAuth:   tls.RequireAnyClientCert,
			},
			Policies:   s.policies,
			Identities: s.identities,
			Cache:      &edge.CacheConfig{},
		})
	}
}

func (s *EdgeServer) Start(store edge.KeyStore) {
	serverCert, err := tls.X509KeyPair(defaultServerCert, defaultServerKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to start EdgeServer: %v", err))
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to start EdgeServer: %v", err))
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)

	apiKey, err := kes.ParseAPIKey(DefaultAPIKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to start EdgeServer: %v", err))
	}
	clientCert, err := kes.GenerateCertificate(apiKey)
	if err != nil {
		panic(fmt.Sprintf("kestest: failed to start EdgeServer: %v", err))
	}

	s.client = kes.NewClientWithConfig("", &tls.Config{
		Certificates:     []tls.Certificate{clientCert},
		RootCAs:          rootCAs,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),
	})
	s.rootCAs = rootCAs
	s.srvCert = serverCert

	ctx, stop := context.WithCancel(context.Background())
	s.stop = stop

	s.store = store

	started := make(chan struct{})
	f := sync.OnceFunc(func() { close(started) })

	s.srv = &edge.Server{}
	s.srv.Register(kessrv.SigStart, f)
	s.srv.Register(kessrv.SigStop, f)
	go func() {
		if err := s.srv.Start(ctx, &mem.Store{}, &edge.Config{
			Addr:  "127.0.0.1:0",
			Admin: DefaultAdmin,
			TLS: &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				ClientAuth:   tls.RequireAnyClientCert,
			},
			Policies:   s.policies,
			Identities: s.identities,
			Cache:      &edge.CacheConfig{},
		}); err != http.ErrServerClosed {
			f()
		}
	}()
	<-started
}

func (es *EdgeServer) Stop() {
	es.stop()
}

var defaultServerCert = []byte(
	`-----BEGIN CERTIFICATE-----
MIIBQjCB9aADAgECAhBWMXxS7NVRT+nPM6Jglai6MAUGAytlcDAUMRIwEAYDVQQD
Ewlsb2NhbGhvc3QwIBcNMjMwODAxMTE0NTMxWhgPMjEyMzA3MDgxMTQ1MzFaMBQx
EjAQBgNVBAMTCWxvY2FsaG9zdDAqMAUGAytlcAMhAJv5QMfmU9jo8Z/ih3srixDs
Y8PzMLwahWt/Gpa/f29ao1swWTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYI
KwYBBQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwGgYDVR0RBBMwEYIJbG9j
YWxob3N0hwR/AAABMAUGAytlcANBACArg1faFeaDeLpNQWOITqJjy1qofM8QEkUr
bGQEmgnRdx2VLdE8FGgO7K+xvIYd2IMHPL17dxQy9G8TpGOwsQM=
-----END CERTIFICATE-----`)

var defaultServerKey = []byte(testingKey(
	`-----BEGIN TESTING KEY-----
MC4CAQAwBQYDK2VwBCIEIFrIWhqdMDUqB9AGb85srarrfDt6/W4BCPxwGlcbd5W2
-----END TESTING KEY-----`))

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }
