// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"context"
	"errors"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/keystore/aws"
	"github.com/minio/kes/internal/keystore/azure"
	"github.com/minio/kes/internal/keystore/fortanix"
	"github.com/minio/kes/internal/keystore/fs"
	"github.com/minio/kes/internal/keystore/gcp"
	"github.com/minio/kes/internal/keystore/gemalto"
	kesstore "github.com/minio/kes/internal/keystore/kes"
	"github.com/minio/kes/internal/keystore/vault"
	"github.com/minio/kes/kv"
)

// ServerConfig is a structure that holds configuration
// for a KES edge server.
type ServerConfig struct {
	// Addr is the network interface address
	// and optional port the KES server will
	// listen on and accept HTTP requests.
	//
	// If only a port number is specified,
	// e.g. ":7373", the KES server listens
	// on all available network interfaces.
	//
	// When a specific IP address is specified,
	// e.g. "127.0.0.1:7373", then KES server
	// listens on only this specific network
	// interface.
	Addr string

	// Admin is the KES server admin identity.
	Admin kes.Identity

	// TLS contains the KES server TLS configuration.
	TLS *TLSConfig

	// Cache contains the KES server cache configuration.
	Cache *CacheConfig

	// Log contains the KES server logging configuration.
	Log *LogConfig

	API *APIConfig

	// Policies contains the KES server policy definitions
	// and statical identity assignments.
	Policies map[string]Policy

	// Keys contains pre-defined keys that the KES server will
	// either create, or expect to exist, before accepting requests.
	Keys []Key

	// KeyStore contains the KES server keystore configuration.
	// The KeyStore manages the keys used by the KES server for
	// encryption and decryption.
	KeyStore KeyStore

	_ [0]int // force usage of struct composite literals with field names
}

// TLSConfig is a structure that holds the TLS configuration
// for a KES server.
type TLSConfig struct {
	// PrivateKey is the path to the KES server's TLS private key.
	PrivateKey string

	// Certificate is the path to the KES server's TLS certificate.
	Certificate string

	// Password is an optional password to decrypt the KES server's
	// private key.
	Password string

	// CAPath is an optional path to a X.509 certificate or directory
	// containing X.509 certificates that the KES server uses, in
	// addition to the system root certificates, as authorities when
	// verify client certificates.
	//
	// If empty, the KES server will only use the system root
	// certificates.
	CAPath string

	// Proxies contains a list of TLS proxy identities.
	// The KES identity of any TLS/HTTPS proxy sitting directly
	// in-front of KES has to be included in this list. A KES
	// server will only accept forwarded client requests from
	// proxies listed here.
	Proxies []kes.Identity

	// ForwardCertHeader is the HTTP header key used by any
	// TLS / HTTPS proxy to forward the actual client certificate
	// to KES.
	ForwardCertHeader string

	_ [0]int
}

// CacheConfig is a structure that holds the Cache configuration
// for a KES server.
type CacheConfig struct {
	// Expiry is the time period after which any cache entries in
	// the key cache are discarded. It determines how often the KES
	// server has to fetch a secret key from the KMS backend.
	Expiry time.Duration

	// ExpiryUnused is the time period after which all unused
	// cache entries in the key cache are discarded. It determines
	// how often "not frequently" used secret keys must be fetched from
	// the KMS backend.
	ExpiryUnused time.Duration

	// ExpiryOffline is the time period after which any cache
	// entries in the offline cache are discarded.
	//
	// It determines how long the KES server can serve stateless
	// requests when the keystore has become unavailable -
	// e.g. due to a network outage.
	//
	// ExpiryOffline is only used while the keystore backend is not
	// available. As long as the keystore is available, the regular
	// cache expiry periods apply.
	ExpiryOffline time.Duration

	_ [0]int
}

// LogConfig is a structure that holds the logging configuration
// for a KES server.
type LogConfig struct {
	// Error determines whether the KES server logs error events to STDERR.
	// It does not en/disable error logging in general.
	Error bool

	// Audit determines whether the KES server logs audit events to STDOUT.
	// It does not en/disable audit logging in general.
	Audit bool

	_ [0]int
}

// APIConfig is a structure that holds the API configuration
// for a KES server.
type APIConfig struct {
	// Paths contains a set of API paths and there
	// API configuration.
	Paths map[string]APIPathConfig

	_ [0]int
}

// APIPathConfig is a structure that holds the API configuration
// for one particular KES API.
type APIPathConfig struct {
	// Timeout is the duration after which the API response
	// with a HTTP timeout error response. If Timeout is
	// zero the API default is used.
	Timeout time.Duration

	// InsecureSkipAuth controls whether the API verifies
	// client identities. If InsecureSkipAuth is true,
	// the API accepts requests from arbitrary identities.
	// In this mode, the API can be used by anyone who can
	// communicate to the KES server over HTTPS.
	// This should only be set for testing or in certain
	// cases for APIs that don't expose sensitive information,
	// like metrics.
	InsecureSkipAuth bool

	_ [0]int
}

// Policy is a structure defining a KES policy.
//
// Any request issued by a KES identity is validated
// by the associated allow and deny patterns. A
// request is accepted if and only if no deny pattern
// and at least one allow pattern matches the request.
type Policy struct {
	// Allow is the list of API path patterns
	// that are explicitly allowed.
	Allow []string

	// Deny is the list of API path patterns
	// that are explicitly denied.
	Deny []string

	// Identities is a list of KES identities
	// that are assigned to this policy.
	//
	// It must not contain the admin or any
	// TLS proxy identity.
	Identities []kes.Identity

	_ [0]int
}

// Key is a structure defining a cryptographic key
// that the KES server will create or ensure exists
// before startup.
type Key struct {
	// Name is the name of the cryptographic key.
	Name string

	_ [0]int
}

// KeyStore is a KES keystore configuration.
//
// Concrete instances implement Connect to return
// a connection to a concrete keystore.
type KeyStore interface {
	// Connect establishes and returns a new connection
	// to the keystore.
	Connect(ctx context.Context) (kv.Store[string, []byte], error)
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

	_ [0]int
}

// Connect returns a kv.Store that stores key-value pairs in a path on the filesystem.
func (s *FSKeyStore) Connect(context.Context) (kv.Store[string, []byte], error) {
	return fs.NewStore(s.Path)
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
func (s *KESKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *VaultKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *FortanixKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *KeySecureKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *GCPSecretManagerKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *AWSSecretsManagerKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
func (s *AzureKeyVaultKeyStore) Connect(ctx context.Context) (kv.Store[string, []byte], error) {
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
