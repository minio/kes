package edgeconf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/minio/kes/edge"
	"github.com/minio/kes/internal/keystore/aws"
	"github.com/minio/kes/internal/keystore/azure"
	"github.com/minio/kes/internal/keystore/entrust"
	"github.com/minio/kes/internal/keystore/fortanix"
	"github.com/minio/kes/internal/keystore/fs"
	"github.com/minio/kes/internal/keystore/gcp"
	"github.com/minio/kes/internal/keystore/gemalto"
	kesstore "github.com/minio/kes/internal/keystore/kes"
	"github.com/minio/kes/internal/keystore/vault"
	"github.com/minio/kes/internal/mtls"
	"gopkg.in/yaml.v3"
)

func Connect(ctx context.Context, r io.Reader) (edge.KeyStore, *edge.Config, error) {
	f, err := Decode(r)
	if err != nil {
		return nil, nil, err
	}
	store, err := f.Connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	return store, f.Config(), nil
}

func Decode(r io.Reader) (*ConfigFile, error) {
	var node yaml.Node
	if err := yaml.NewDecoder(r).Decode(&node); err != nil {
		return nil, err
	}

	version, err := findVersion(&node)
	if err != nil {
		return nil, err
	}
	const Version = "v1"
	if version != "" && version != Version {
		return nil, fmt.Errorf("edge: invalid server config version '%s'", version)
	}

	var y yml
	if err := node.Decode(&y); err != nil {
		return nil, err
	}
	return decode(&y)
}

type ConfigFile struct {
	config   *edge.Config
	keystore keystore
}

func (c *ConfigFile) Config() *edge.Config { return c.config.Clone() }

func (c *ConfigFile) Connect(ctx context.Context) (edge.KeyStore, error) {
	return c.keystore.Connect(ctx)
}

type keystore interface {
	Connect(context.Context) (edge.KeyStore, error)
}

// FSKeyStore is a structure containing the configuration
// for a simple filesystem keystore.
//
// A FSKeyStore should only be used when testing a KES server.
type FSKeyStore struct {
	// Path is the path to the directory that
	// contains the keys.
	//
	// If the directory does not exist, it
	// will be created.
	Path string
}

// Connect returns a kv.Store that stores key-value pairs in a path on the filesystem.
func (s *FSKeyStore) Connect(context.Context) (edge.KeyStore, error) {
	return fs.New(s.Path)
}

// KESKeyStore is a structure containing the configuration
// for using a KES server/cluster as key store.
type KESKeyStore struct {
	// Endpoints is a set of KES server endpoints.
	//
	// If multiple endpoints are provided, the requests
	// will be automatically balanced across them.
	Endpoints []string

	// Enclave is an optional enclave name. If empty,
	// the default enclave name will be used.
	Enclave string

	// CertificateFile is a path to a mTLS client
	// certificate file used to authenticate to
	// the KES server.
	CertificateFile string

	// PrivateKeyFile is a path to a mTLS private
	// key used to authenticate to the KES server.
	PrivateKeyFile string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KES server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath string
}

// Connect returns a kv.Store that stores key-value pairs on a KES server.
func (s *KESKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	return kesstore.Connect(ctx, &kesstore.Config{
		Endpoints:   s.Endpoints,
		Enclave:     s.Enclave,
		Certificate: s.CertificateFile,
		PrivateKey:  s.PrivateKeyFile,
		CAPath:      s.CAPath,
	})
}

// VaultKeyStore is a structure containing the configuration
// for Hashicorp Vault.
type VaultKeyStore struct {
	// Endpoint is the Hashicorp Vault endpoint.
	Endpoint string

	// Namespace is an optional Hashicorp Vault namespace.
	// An empty namespace means no particular namespace
	// is used.
	Namespace string

	// APIVersion is the API version of the Hashicorp Vault
	// K/V engine. Valid values are: "v1" and "v2".
	// If empty, defaults to "v1".
	APIVersion string

	// Engine is the Hashicorp Vault K/V engine path.
	// If empty, defaults to "kv".
	Engine string

	// Prefix is an optional prefix / directory within the
	// K/V engine.
	// If empty, keys will be stored at the K/V engine top
	// level.
	Prefix string

	// AppRole contains the Vault AppRole authentication
	// method credentials.
	AppRole *VaultAppRoleAuth

	// Kubernetes contains the Vault Kubernetes authentication
	// method credentials.
	Kubernetes *VaultKubernetesAuth

	// PrivateKey is an optional path to a
	// TLS private key file containing a
	// TLS private key for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	PrivateKey string

	// Certificate is an optional path to a
	// TLS certificate file containing a
	// TLS certificate for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	Certificate string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the Hashicorp Vault server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath string

	// StatusPing controls how often to Vault health status
	// is checked.
	// If not set, defaults to 10s.
	StatusPing time.Duration

	_ [0]int
}

// VaultAppRoleAuth is a structure containing the configuration
// for the Hashicorp Vault AppRole authentication method.
type VaultAppRoleAuth struct {
	// AppRoleEngine is the AppRole authentication engine path.
	// If empty, defaults to "approle".
	Engine string

	// AppRoleID is the AppRole access ID for authenticating
	// to Hashicorp Vault via the AppRole method.
	ID string

	// AppRoleSecret is the AppRole access secret for authenticating
	// to Hashicorp Vault via the AppRole method.
	Secret string
}

// VaultKubernetesAuth is a structure containing the configuration
// for the Hashicorp Vault Kubernetes authentication method.
type VaultKubernetesAuth struct {
	// KubernetesEngine is the Kubernetes authentication engine path.
	// If empty, defaults to "kubernetes".
	Engine string

	// KubernetesRole is the login role for authenticating via the
	// kubernetes authentication method.
	Role string

	// KubernetesJWT is either the JWT or a path to a file containing
	// the JWT for for authenticating via the kubernetes authentication
	// method.
	JWT string
}

// Connect returns a kv.Store that stores key-value pairs on a Hashicorp Vault server.
func (s *VaultKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	if s.AppRole == nil && s.Kubernetes == nil {
		return nil, errors.New("edge: failed to connect to hashicorp vault: no authentication method specified")
	}
	if s.AppRole != nil && s.Kubernetes != nil {
		return nil, errors.New("edge: failed to connect to hashicorp vault: more than one authentication method specified")
	}
	c := &vault.Config{
		Endpoint:        s.Endpoint,
		Engine:          s.Engine,
		APIVersion:      s.APIVersion,
		Namespace:       s.Namespace,
		Prefix:          s.Prefix,
		PrivateKey:      s.PrivateKey,
		Certificate:     s.Certificate,
		CAPath:          s.CAPath,
		StatusPingAfter: s.StatusPing,
	}
	if s.AppRole != nil {
		c.AppRole = vault.AppRole{
			Engine: s.AppRole.Engine,
			ID:     s.AppRole.ID,
			Secret: s.AppRole.Secret,
		}
	}
	if s.Kubernetes != nil {
		c.K8S = vault.Kubernetes{
			Engine: s.Kubernetes.Engine,
			Role:   s.Kubernetes.Role,
			JWT:    s.Kubernetes.JWT,
		}
	}
	return vault.Connect(ctx, c)
}

// FortanixKeyStore is a structure containing the
// configuration for Fortanix SDKMS.
type FortanixKeyStore struct {
	// Endpoint is the endpoint of the Fortanix KMS.
	Endpoint string

	// GroupID is the ID of the access control group.
	GroupID string

	// APIKey is the API key for authenticating to
	// the Fortanix KMS.
	APIKey string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the Hashicorp Vault server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath string

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs on a Fortanix SDKMS server.
func (s *FortanixKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	return fortanix.Connect(ctx, &fortanix.Config{
		Endpoint: s.Endpoint,
		GroupID:  s.GroupID,
		APIKey:   fortanix.APIKey(s.APIKey),
		CAPath:   s.CAPath,
	})
}

// KeySecureKeyStore is a structure containing the
// configuration for Gemalto KeySecure / Thales
// CipherTrust Manager.
type KeySecureKeyStore struct {
	// Endpoint is the endpoint to the KeySecure server.
	Endpoint string

	// Token is the refresh authentication token to
	// access the KeySecure server.
	Token string

	// Domain is the isolated namespace within the
	// KeySecure server. If empty, defaults to the
	// top-level / root domain.
	Domain string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KeySecure server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath string

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs on a Gemalto KeySecure instance.
func (s *KeySecureKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	return gemalto.Connect(ctx, &gemalto.Config{
		Endpoint: s.Endpoint,
		CAPath:   s.CAPath,
		Login: gemalto.Credentials{
			Token:  s.Token,
			Domain: s.Domain,
		},
	})
}

// GCPSecretManagerKeyStore is a structure containing the
// configuration for GCP SecretManager.
type GCPSecretManagerKeyStore struct {
	// ProjectID is the GCP project ID.
	ProjectID string

	// Endpoint is the GCP project ID. If empty,
	// defaults to:
	//   secretmanager.googleapis.com:443
	Endpoint string

	// Scopes are GCP OAuth2 scopes for accessing
	// GCP APIs. If empty, defaults to the GCP
	// default scopes.
	Scopes []string

	// ClientEmail is the Client email of the
	// GCP service account used to access the
	// SecretManager.
	ClientEmail string

	// ClientID is the Client ID of the GCP
	// service account used to access the
	// SecretManager.
	ClientID string

	// KeyID is the private key ID of the GCP
	// service account used to access the
	// SecretManager.
	KeyID string

	// Key is the private key of the GCP
	// service account used to access the
	// SecretManager.
	Key string

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs on GCP SecretManager.
func (s *GCPSecretManagerKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	return gcp.Connect(ctx, &gcp.Config{
		Endpoint:  s.Endpoint,
		ProjectID: s.ProjectID,
		Scopes:    s.Scopes,
		Credentials: gcp.Credentials{
			ClientID: s.ClientID,
			Client:   s.ClientEmail,
			KeyID:    s.KeyID,
			Key:      s.Key,
		},
	})
}

// AWSSecretsManagerKeyStore is a structure containing the
// configuration for AWS SecretsManager.
type AWSSecretsManagerKeyStore struct {
	// Endpoint is the AWS SecretsManager endpoint.
	// AWS SecretsManager endpoints have the following
	// schema:
	//  secrestmanager[-fips].<region>.amanzonaws.com
	Endpoint string

	// Region is the AWS region the SecretsManager is
	// located.
	Region string

	// KMSKey is the AWS-KMS key ID (CMK-ID) used to
	// to en/decrypt secrets managed by the SecretsManager.
	// If empty, the default AWS KMS key is used.
	KMSKey string

	// AccessKey is the access key for authenticating to AWS.
	AccessKey string

	// SecretKey is the secret key for authenticating to AWS.
	SecretKey string

	// SessionToken is an optional session token for authenticating
	// to AWS.
	SessionToken string

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs on AWS SecretsManager.
func (s *AWSSecretsManagerKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	return aws.Connect(ctx, &aws.Config{
		Addr:     s.Endpoint,
		Region:   s.Region,
		KMSKeyID: s.KMSKey,
		Login: aws.Credentials{
			AccessKey:    s.AccessKey,
			SecretKey:    s.SecretKey,
			SessionToken: s.SessionToken,
		},
	})
}

// AzureKeyVaultKeyStore is a structure containing the
// configuration for Azure KeyVault.
type AzureKeyVaultKeyStore struct {
	// Endpoint is the Azure KeyVault endpoint.
	Endpoint string

	// TenantID is the ID of the Azure KeyVault tenant.
	TenantID string

	// ClientID is the ID of the client accessing
	// Azure KeyVault.
	ClientID string

	// ClientSecret is the client secret accessing the
	// Azure KeyVault.
	ClientSecret string

	// ManagedIdentityClientID is the client ID of the
	// Azure managed identity that access the KeyVault.
	ManagedIdentityClientID string

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs on Azure KeyVault.
func (s *AzureKeyVaultKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	if (s.TenantID != "" || s.ClientID != "" || s.ClientSecret != "") && s.ManagedIdentityClientID != "" {
		return nil, errors.New("edge: failed to connect to Azure KeyVault: more than one authentication method specified")
	}
	switch {
	case s.TenantID != "" || s.ClientID != "" || s.ClientSecret != "":
		creds := azure.Credentials{
			TenantID: s.TenantID,
			ClientID: s.ClientID,
			Secret:   s.ClientSecret,
		}
		return azure.ConnectWithCredentials(ctx, s.Endpoint, creds)
	case s.ManagedIdentityClientID != "":
		creds := azure.ManagedIdentity{
			ClientID: s.ManagedIdentityClientID,
		}
		return azure.ConnectWithIdentity(ctx, s.Endpoint, creds)
	default:
		return nil, errors.New("edge: failed to connect to Azure KeyVault: no authentication method specified")
	}
}

// EntrustKeyControlKeyStore is a structure containing the
// configuration for Entrust KeyControl.
type EntrustKeyControlKeyStore struct {
	// Endpoint is the Entrust KeyControl endpoint.
	Endpoint string

	// VaultID is the KeyControl Vault UUID.
	VaultID string

	// BoxID is the KeyControl box ID or name within the Vault.
	BoxID string

	// Username is the username used for authentication.
	Username string

	// Password is the password associated with the provided username.
	Password string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KeyControl server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath string
}

// Connect returns a kv.Store that stores key-value pairs on Entrust KeyControl.
func (s *EntrustKeyControlKeyStore) Connect(ctx context.Context) (edge.KeyStore, error) {
	var rootCAs *x509.CertPool
	if s.CAPath != "" {
		ca, err := mtls.CertPoolFromFile(s.CAPath)
		if err != nil {
			return nil, err
		}
		rootCAs = ca
	}
	return entrust.Login(ctx, &entrust.Config{
		Endpoint: s.Endpoint,
		VaultID:  s.VaultID,
		BoxID:    s.BoxID,
		Username: s.Username,
		Password: s.Password,
		TLS: &tls.Config{
			RootCAs: rootCAs,
		},
	})
}
