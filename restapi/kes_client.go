package restapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/pkg/env"
)

type KESClientI interface {
	listKeys(ctx context.Context, pattern string) (*kes.KeyIterator, error)
	listIdentities(ctx context.Context, pattern string) (*kes.IdentityIterator, error)
	listPolicies(ctx context.Context, pattern string) (*kes.PolicyIterator, error)
}

type KESClient struct {
	Client *kes.Client
}

func (k KESClient) listKeys(ctx context.Context, pattern string) (*kes.KeyIterator, error) {
	return k.Client.ListKeys(ctx, pattern)
}

func (k KESClient) listIdentities(ctx context.Context, pattern string) (*kes.IdentityIterator, error) {
	return k.Client.ListIdentities(ctx, pattern)
}

func (k KESClient) listPolicies(ctx context.Context, pattern string) (*kes.PolicyIterator, error) {
	return k.Client.ListPolicies(ctx, pattern)
}

func NewKESClient() (*kes.Client, error) {
	const DefaultServer = "https://127.0.0.1:7373"
	// TODO: Change insecureSKipVerify to false
	insecureSkipVerify := true
	insecure, ok := os.LookupEnv("CONSOLE_KES_INSECURE")
	if ok && strings.ToLower(insecure) == "true" {
		insecureSkipVerify = true
	}
	certPath, ok := os.LookupEnv("CONSOLE_KES_CLIENT_CERT")
	if !ok {
		return nil, errors.New("no TLS client certificate. Environment variable 'CONSOLE_KES_CLIENT_CERT' is not set")
	}
	if strings.TrimSpace(certPath) == "" {
		return nil, errors.New("no TLS client certificate. Environment variable 'CONSOLE_KES_CLIENT_CERT' is empty")
	}

	keyPath, ok := os.LookupEnv("CONSOLE_KES_CLIENT_KEY")
	if !ok {
		return nil, errors.New("no TLS private key. Environment variable 'CONSOLE_KES_CLIENT_KEY' is not set")
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, errors.New("no TLS private key. Environment variable 'CONSOLE_KES_CLIENT_KEY' is empty")
	}

	certPem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %v", err)
	}
	certPem, err = xhttp.FilterPEM(certPem, func(b *pem.Block) bool { return b.Type == "CERTIFICATE" })
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %v", err)
	}
	keyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS private key: %v", err)
	}

	privateKey, rest := pem.Decode(bytes.TrimSpace(keyPem))

	if len(rest) != 0 {
		cli.Fatalf("failed to read TLS private key: %v", err)
	}
	if x509.IsEncryptedPEMBlock(privateKey) {

		decPrivateKey, err := x509.DecryptPEMBlock(privateKey, []byte(env.Get("CONSOLE_KES_CLIENT_PASSWORD", "")))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %v", err)
		}
		keyPem = pem.EncodeToMemory(&pem.Block{Type: privateKey.Type, Bytes: decPrivateKey})
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		cli.Fatalf("failed to load TLS private key or certificate: %v", err)
	}

	addr := DefaultServer
	if env, ok := os.LookupEnv("CONSOLE_KES_SERVER"); ok {
		addr = env
	}
	return kes.NewClientWithConfig(addr, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: insecureSkipVerify,
	}), nil
}
