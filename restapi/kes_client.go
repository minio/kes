package restapi

import (
	"context"
	"crypto/tls"
	"errors"
	"os"

	"github.com/minio/kes-go"
	"github.com/minio/kes/models"
)

// KESClientI interface for KESClient
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

// KESClient is a wrapper around the KES client
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

func newKESClient(session *models.Principal) (*kes.Client, error) {
	const DefaultServer = "https://127.0.0.1:7373"
	cert, err := getKESCertificate(session)
	if err != nil {
		return nil, err
	}
	addr := DefaultServer
	if env, ok := os.LookupEnv("KES_SERVER"); ok {
		addr = env
	}
	return kes.NewClientWithConfig(addr, &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: session.Insecure,
	}), nil
}

func getKESCertificate(session *models.Principal) (tls.Certificate, error) {
	if session.APIKey != "" {
		if session.ClientCertificate != "" || session.ClientKey != "" {
			return tls.Certificate{}, errors.New("cannot use both API key and client certificate and key")
		}
		key, err := kes.ParseAPIKey(session.APIKey)
		if err != nil {
			return tls.Certificate{}, err
		}
		return kes.GenerateCertificate(key)
	}
	return tls.X509KeyPair([]byte(session.ClientCertificate), []byte(session.ClientKey))
}
