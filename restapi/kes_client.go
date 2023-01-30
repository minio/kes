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
	status(ctx context.Context) (kes.State, error)
	metrics(ctx context.Context) (kes.Metric, error)
	apis(ctx context.Context) ([]kes.API, error)
	version(ctx context.Context) (string, error)
	describeKey(ctx context.Context, name string) (*kes.KeyInfo, error)
	createKey(ctx context.Context, name string) error
	deleteKey(ctx context.Context, name string) error
	importKey(ctx context.Context, name string, key []byte) error
	listKeys(ctx context.Context, pattern string) (*kes.KeyIterator, error)
	setPolicy(ctx context.Context, name string, policy *kes.Policy) error
	assignPolicy(ctx context.Context, name, identity string) error
	describePolicy(ctx context.Context, name string) (*kes.PolicyInfo, error)
	getPolicy(ctx context.Context, name string) (*kes.Policy, error)
	listPolicies(ctx context.Context, pattern string) (*kes.PolicyIterator, error)
	deletePolicy(ctx context.Context, name string) error
	describeIdentity(ctx context.Context, name string) (*kes.IdentityInfo, error)
	describeSelfIdentity(ctx context.Context) (*kes.IdentityInfo, *kes.Policy, error)
	listIdentities(ctx context.Context, pattern string) (*kes.IdentityIterator, error)
	deleteIdentity(ctx context.Context, name string) error
}

type KESClient struct {
	Client *kes.Client
}

func (k KESClient) status(ctx context.Context) (kes.State, error) {
	return k.Client.Status(ctx)
}

func (k KESClient) metrics(ctx context.Context) (kes.Metric, error) {
	return k.Client.Metrics(ctx)
}

func (k KESClient) apis(ctx context.Context) ([]kes.API, error) {
	return k.Client.APIs(ctx)
}

func (k KESClient) version(ctx context.Context) (string, error) {
	return k.Client.Version(ctx)
}

func (k KESClient) describeKey(ctx context.Context, name string) (*kes.KeyInfo, error) {
	return k.Client.DescribeKey(ctx, name)
}

func (k KESClient) createKey(ctx context.Context, name string) error {
	return k.Client.CreateKey(ctx, name)
}

func (k KESClient) deleteKey(ctx context.Context, name string) error {
	return k.Client.DeleteKey(ctx, name)
}

func (k KESClient) importKey(ctx context.Context, name string, key []byte) error {
	return k.Client.ImportKey(ctx, name, key)
}

func (k KESClient) listKeys(ctx context.Context, pattern string) (*kes.KeyIterator, error) {
	return k.Client.ListKeys(ctx, pattern)
}

func (k KESClient) setPolicy(ctx context.Context, name string, policy *kes.Policy) error {
	return k.Client.SetPolicy(ctx, name, policy)
}

func (k KESClient) assignPolicy(ctx context.Context, name, identity string) error {
	return k.Client.AssignPolicy(ctx, name, kes.Identity(identity))
}

func (k KESClient) describePolicy(ctx context.Context, name string) (*kes.PolicyInfo, error) {
	return k.Client.DescribePolicy(ctx, name)
}

func (k KESClient) getPolicy(ctx context.Context, name string) (*kes.Policy, error) {
	return k.Client.GetPolicy(ctx, name)
}

func (k KESClient) listPolicies(ctx context.Context, pattern string) (*kes.PolicyIterator, error) {
	return k.Client.ListPolicies(ctx, pattern)
}

func (k KESClient) deletePolicy(ctx context.Context, name string) error {
	return k.Client.DeletePolicy(ctx, name)
}

func (k KESClient) listIdentities(ctx context.Context, pattern string) (*kes.IdentityIterator, error) {
	return k.Client.ListIdentities(ctx, pattern)
}

func (k KESClient) describeIdentity(ctx context.Context, name string) (*kes.IdentityInfo, error) {
	return k.Client.DescribeIdentity(ctx, kes.Identity(name))
}

func (k KESClient) describeSelfIdentity(ctx context.Context) (*kes.IdentityInfo, *kes.Policy, error) {
	return k.Client.DescribeSelf(ctx)
}

func (k KESClient) deleteIdentity(ctx context.Context, name string) error {
	return k.Client.DeleteIdentity(ctx, kes.Identity(name))
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
