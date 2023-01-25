// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/keystore/aws"
	"github.com/minio/kes/internal/keystore/azure"
	"github.com/minio/kes/internal/keystore/fortanix"
	"github.com/minio/kes/internal/keystore/fs"
	"github.com/minio/kes/internal/keystore/gcp"
	"github.com/minio/kes/internal/keystore/gemalto"
	"github.com/minio/kes/internal/keystore/generic"
	"github.com/minio/kes/internal/keystore/mem"
	"github.com/minio/kes/internal/keystore/vault"
	"github.com/minio/kes/kms"
	"gopkg.in/yaml.v3"
)

// DecodeServerConfig parses and returns a new ServerConfig
// from an io.Reader.
func DecodeServerConfig(r io.Reader) (*ServerConfig, error) {
	const Version = "v1"

	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(false)

	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return nil, err
	}

	version, err := findVersion(&node)
	if err != nil {
		return nil, err
	}
	if version != "" && version != Version {
		return nil, errors.New("keserv: invalid server config version '" + version + "'")
	}

	var config serverConfigYAML
	if err := node.Decode(&config); err != nil {
		return nil, err
	}
	return yamlToServerConfig(&config), nil
}

// EncodeServerConfig encodes and writes the ServerConfig to
// an io.Writer
func EncodeServerConfig(w io.Writer, config *ServerConfig) error {
	return yaml.NewEncoder(w).Encode(serverConfigToYAML(config))
}

// ReadServerConfig parses and returns a new ServerConfig from
// a file.
func ReadServerConfig(filename string) (*ServerConfig, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config, err := DecodeServerConfig(file)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return config, nil
}

// WriteServerConfig encodes and writes the ServerConfig to
// a file.
func WriteServerConfig(filename string, config *ServerConfig) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := EncodeServerConfig(file, config); err != nil {
		return err
	}
	return file.Close()
}

// findVersion finds the version field in the
// the given YAML document AST.
//
// If the top level of the AST does not contain
// a version field the returned version is empty.
func findVersion(root *yaml.Node) (string, error) {
	if root == nil {
		return "", errors.New("keserv: invalid server config")
	}
	if root.Kind != yaml.DocumentNode {
		return "", errors.New("keserv: invalid server config")
	}
	if len(root.Content) != 1 {
		return "", errors.New("keserv: invalid server config")
	}

	doc := root.Content[0]
	for i, n := range doc.Content {
		if n.Value == "version" {
			if n.Kind != yaml.ScalarNode {
				return "", errors.New("keserv: invalid server config version at line " + strconv.Itoa(n.Line))
			}
			if i == len(doc.Content)-1 {
				return "", errors.New("keserv: invalid server config version at line " + strconv.Itoa(n.Line))
			}
			v := doc.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				return "", errors.New("keserv: invalid server config version at line " + strconv.Itoa(v.Line))
			}
			return v.Value, nil
		}
	}
	return "", nil
}

// ServerConfig is a structure that holds configuration
// for a (stateless) KES server.
type ServerConfig struct {
	// Addr is the KES server address.
	//
	// It should be an IP or FQDN with
	// an optional port number separated
	// by ':'.
	Addr Env[string]

	// Admin is the KES server admin identity.
	Admin Env[kes.Identity]

	// TLS holds the KES server TLS configuration.
	TLS TLSConfig

	// Cache holds the KES server cache configuration.
	Cache CacheConfig

	// Log holds the KES server logging configuration.
	Log LogConfig

	// Policies contains the KES server policy definitions
	// and static identity assignments.
	Policies map[string]Policy

	// Keys contains pre-defined keys that the KES server
	// will create on before startup.
	Keys []Key

	// KMS holds the KES server KMS backend configuration.
	KMS KMSConfig

	_ [0]int // force usage of struct composite literals with field names
}

// TLSConfig is a structure that holds the TLS configuration
// for a (stateless) KES server.
type TLSConfig struct {
	// PrivateKey is the path to the KES server's TLS private key.
	PrivateKey Env[string]

	// Certificate is the path to the KES server's TLS certificate.
	Certificate Env[string]

	// CAPath is an optional path to a X.509 certificate or directory
	// containing X.509 certificates that the KES server uses, in
	// addition to the system root certificates, as authorities when
	// verify client certificates.
	//
	// If empty, the KES server will only use the system root
	// certificates.
	CAPath Env[string]

	// Password is an optional password to decrypt the KES server's
	// private key.
	Password Env[string]

	// Proxies contains a list of TLS proxy identities.
	// The KES identity of any TLS/HTTPS proxy sitting directly
	// in-front of KES has to be included in this list. A KES
	// server will only accept forwarded client requests from
	// proxies listed here.
	Proxies []Env[kes.Identity]

	// ForwardCertHeader is the HTTP header key used by any
	// TLS / HTTPS proxy to forward the actual client certificate
	// to KES.
	ForwardCertHeader Env[string]

	_ [0]int
}

// CacheConfig is a structure that holds the Cache configuration
// for a (stateless) KES server.
type CacheConfig struct {
	// Expiry is the time period after which any cache entries
	// are discarded. It determines how often the KES server has
	// to fetch a secret key from the KMS backend.
	Expiry Env[time.Duration]

	// ExpiryUnused is the time period after which all unused
	// cache entries are discarded. It determines how often
	// "not frequently" used secret keys must be fetched from
	// the KMS backend.
	ExpiryUnused Env[time.Duration]

	// ExpiryOffline is the time period after which any cache
	// entries in the offline cache are discarded.
	//
	// It determines how long the KES server can serve stateless
	// requests when the KMS has become unavailable -
	// e.g. due to a network outage.
	//
	// ExpiryOffline is only used while the KMS backend is not
	// available. As long as the KMS is available, the regular
	// cache expiry periods apply.
	ExpiryOffline Env[time.Duration]

	_ [0]int
}

// LogConfig is a structure that holds the logging configuration
// for a (stateless) KES server.
type LogConfig struct {
	// Error enables/disables logging audit events to STDOUT.
	// Valid values are "on" and "off".
	Audit Env[string]

	// Error enables/disables logging error events to STDERR.
	// Valid values are "on" and "off".
	Error Env[string]

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
	Identities []Env[kes.Identity]

	_ [0]int
}

// Key is a structure defining a cryptographic key
// that the KES server will create before startup.
type Key struct {
	// Name is the name of the cryptographic key.
	Name Env[string]

	_ [0]int
}

// KMSConfig represents a KMS configuration.
//
// Concrete instances implement Connect to
// return a connection to a concrete KMS instance.
type KMSConfig interface {
	// Connect establishes and returns a new connection
	// to the KMS.
	Connect(ctx context.Context) (kms.Conn, error)

	toYAML(yml *serverConfigYAML)

	fromYAML(yml *serverConfigYAML)
}

type memConfig struct{}

func (*memConfig) Connect(context.Context) (kms.Conn, error) { return new(mem.Store), nil }
func (*memConfig) toYAML(*serverConfigYAML)                  {}
func (*memConfig) fromYAML(*serverConfigYAML)                {}

// FSConfig is a structure containing the configuration
// for a simple filesystem KMS.
//
// A FSConfig should only be used when testing a KES server.
type FSConfig struct {
	// Dir is the path to the directory that
	// contains the keys.
	//
	// If the directory does not exist, it
	// will be created when establishing
	// a connection to the filesystem.
	Dir Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the OS filesystem.
func (c *FSConfig) Connect(context.Context) (kms.Conn, error) { return fs.NewConn(c.Dir.Value) }

func (c *FSConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Fs.Path = c.Dir
}

func (c *FSConfig) fromYAML(yml *serverConfigYAML) {
	c.Dir = yml.KeyStore.Fs.Path
}

// KMSPluginConfig is a structure containing the
// configuration for a KMS plugin.
type KMSPluginConfig struct {
	// Endpoint is the endpoint of the KMS plugin.
	Endpoint Env[string]

	// PrivateKey is an optional path to a
	// TLS private key file containing a
	// TLS private key for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	PrivateKey Env[string]

	// Certificate is an optional path to a
	// TLS certificate file containing a
	// TLS certificate for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	Certificate Env[string]

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KMS plugin.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath Env[string]
}

// Connect establishes and returns a kms.Conn to the
// KMS plugin.
func (c *KMSPluginConfig) Connect(ctx context.Context) (kms.Conn, error) {
	return generic.Connect(ctx, &generic.Config{
		Endpoint:    c.Endpoint.Value,
		PrivateKey:  c.PrivateKey.Value,
		Certificate: c.Certificate.Value,
		CAPath:      c.CAPath.Value,
	})
}

func (c *KMSPluginConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Generic.Endpoint = c.Endpoint
	yml.KeyStore.Generic.TLS.PrivateKey = c.PrivateKey
	yml.KeyStore.Generic.TLS.Certificate = c.Certificate
	yml.KeyStore.Generic.TLS.CAPath = c.CAPath
}

func (c *KMSPluginConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Generic.Endpoint
	c.PrivateKey = yml.KeyStore.Generic.TLS.PrivateKey
	c.Certificate = yml.KeyStore.Generic.TLS.Certificate
	c.CAPath = yml.KeyStore.Generic.TLS.CAPath
}

// VaultConfig is a structure containing the
// configuration for Hashicorp Vault.
type VaultConfig struct {
	// Endpoint is the Hashicorp Vault endpoint.
	Endpoint Env[string]

	// Namespace is an optional Hashicorp Vault namespace.
	// An empty namespace means no particular namespace
	// is used.
	Namespace Env[string]

	// APIVersion is the API version of the Hashicorp Vault
	// K/V engine. Valid values are: "v1" and "v2".
	// If empty, defaults to "v1".
	APIVersion Env[string]

	// Engine is the Hashicorp Vault K/V engine path.
	// If empty, defaults to "kv".
	Engine Env[string]

	// Prefix is an optional prefix / directory within the
	// K/V engine.
	// If empty, keys will be stored at the K/V engine top
	// level.
	Prefix Env[string]

	// AppRoleEngine is the AppRole authentication engine path.
	// If empty, defaults to "approle".
	AppRoleEngine Env[string]

	// AppRoleID is the AppRole access ID for authenticating
	// to Hashicorp Vault via the AppRole method.
	AppRoleID Env[string]

	// AppRoleSecret is the AppRole access secret for authenticating
	// to Hashicorp Vault via the AppRole method.
	AppRoleSecret Env[string]

	// AppRoleRetry is the retry delay between authentication attempts.
	// If not set, defaults to 15s.
	AppRoleRetry Env[time.Duration]

	// KubernetesEngine is the Kubernetes authentication engine path.
	// If empty, defaults to "kubernetes".
	KubernetesEngine Env[string]

	// KubernetesRole is the login role for authenticating via the
	// kubernetes authentication method.
	KubernetesRole Env[string]

	// KubernetesJWT is either the JWT or a path to a file containing
	// the JWT for for authenticating via the kubernetes authentication
	// method.
	KubernetesJWT Env[string]

	// KubernetesRetry is the retry delay between authentication attempts.
	// If not set, defaults to 15s.
	KubernetesRetry Env[time.Duration]

	// PrivateKey is an optional path to a
	// TLS private key file containing a
	// TLS private key for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	PrivateKey Env[string]

	// Certificate is an optional path to a
	// TLS certificate file containing a
	// TLS certificate for mTLS authentication.
	//
	// If empty, mTLS authentication is disabled.
	Certificate Env[string]

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the Hashicorp Vault server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath Env[string]

	// StatusPing controls how often to Vault health status
	// is checked.
	// If not set, defaults to 10s.
	StatusPing Env[time.Duration]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to Hashicorp Vault.
func (c *VaultConfig) Connect(ctx context.Context) (kms.Conn, error) {
	config := &vault.Config{
		Endpoint:   c.Endpoint.Value,
		Engine:     c.Engine.Value,
		APIVersion: c.APIVersion.Value,
		Namespace:  c.Namespace.Value,
		Prefix:     c.Prefix.Value,
		AppRole: vault.AppRole{
			Engine: c.AppRoleEngine.Value,
			ID:     c.AppRoleID.Value,
			Secret: c.AppRoleSecret.Value,
			Retry:  c.AppRoleRetry.Value,
		},
		K8S: vault.Kubernetes{
			Engine: c.KubernetesEngine.Value,
			Role:   c.KubernetesRole.Value,
			JWT:    c.KubernetesJWT.Value,
			Retry:  c.KubernetesRetry.Value,
		},
		PrivateKey:      c.PrivateKey.Value,
		Certificate:     c.Certificate.Value,
		CAPath:          c.CAPath.Value,
		StatusPingAfter: c.StatusPing.Value,
	}
	return vault.Connect(ctx, config)
}

func (c *VaultConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Vault.Endpoint = c.Endpoint
	yml.KeyStore.Vault.Namespace = c.Namespace
	yml.KeyStore.Vault.APIVersion = c.APIVersion
	yml.KeyStore.Vault.Engine = c.Engine
	yml.KeyStore.Vault.Prefix = c.Prefix
	yml.KeyStore.Vault.AppRole.Engine = c.AppRoleEngine
	yml.KeyStore.Vault.AppRole.ID = c.AppRoleID
	yml.KeyStore.Vault.AppRole.Secret = c.AppRoleSecret
	yml.KeyStore.Vault.AppRole.Retry = c.AppRoleRetry
	yml.KeyStore.Vault.Kubernetes.Engine = c.KubernetesEngine
	yml.KeyStore.Vault.Kubernetes.Role = c.KubernetesRole
	yml.KeyStore.Vault.Kubernetes.JWT = c.KubernetesJWT
	yml.KeyStore.Vault.Kubernetes.Retry = c.KubernetesRetry
	yml.KeyStore.Vault.TLS.PrivateKey = c.PrivateKey
	yml.KeyStore.Vault.TLS.Certificate = c.Certificate
	yml.KeyStore.Vault.TLS.CAPath = c.CAPath
	yml.KeyStore.Vault.Status.Ping = c.StatusPing
}

func (c *VaultConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Vault.Endpoint
	c.Namespace = yml.KeyStore.Vault.Namespace
	c.APIVersion = yml.KeyStore.Vault.APIVersion
	c.Engine = yml.KeyStore.Vault.Engine
	c.Prefix = yml.KeyStore.Vault.Prefix
	c.AppRoleEngine = yml.KeyStore.Vault.AppRole.Engine
	c.AppRoleID = yml.KeyStore.Vault.AppRole.ID
	c.AppRoleSecret = yml.KeyStore.Vault.AppRole.Secret
	c.AppRoleRetry = yml.KeyStore.Vault.AppRole.Retry
	c.KubernetesEngine = yml.KeyStore.Vault.Kubernetes.Engine
	c.KubernetesRole = yml.KeyStore.Vault.Kubernetes.Role
	c.KubernetesJWT = yml.KeyStore.Vault.Kubernetes.JWT
	c.KubernetesRetry = yml.KeyStore.Vault.Kubernetes.Retry
	c.PrivateKey = yml.KeyStore.Vault.TLS.PrivateKey
	c.Certificate = yml.KeyStore.Vault.TLS.Certificate
	c.CAPath = yml.KeyStore.Vault.TLS.CAPath
	c.StatusPing = yml.KeyStore.Vault.Status.Ping
}

// FortanixConfig is a structure containing the
// configuration for FortanixConfig SDKMS.
type FortanixConfig struct {
	// Endpoint is the endpoint of the Fortanix KMS.
	Endpoint Env[string]

	// GroupID is the ID of the access control group.
	GroupID Env[string]

	// APIKey is the API key for authenticating to
	// the Fortanix KMS.
	APIKey Env[string]

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the Hashicorp Vault server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the Fortanix KMS.
func (c *FortanixConfig) Connect(ctx context.Context) (kms.Conn, error) {
	return fortanix.Connect(ctx, &fortanix.Config{
		Endpoint: c.Endpoint.Value,
		GroupID:  c.GroupID.Value,
		APIKey:   fortanix.APIKey(c.APIKey.Value),
		CAPath:   c.CAPath.Value,
	})
}

func (c *FortanixConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Fortanix.SDKMS.Endpoint = c.Endpoint
	yml.KeyStore.Fortanix.SDKMS.GroupID = c.GroupID
	yml.KeyStore.Fortanix.SDKMS.Login.APIKey = c.APIKey
	yml.KeyStore.Fortanix.SDKMS.TLS.CAPath = c.CAPath
}

func (c *FortanixConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Fortanix.SDKMS.Endpoint
	c.GroupID = yml.KeyStore.Fortanix.SDKMS.GroupID
	c.APIKey = yml.KeyStore.Fortanix.SDKMS.Login.APIKey
	c.CAPath = yml.KeyStore.Fortanix.SDKMS.TLS.CAPath
}

// SecretsManagerConfig is a structure containing the
// configuration for AWS SecretsManager.
type SecretsManagerConfig struct {
	// Endpoint is the AWS SecretsManager endpoint.
	// AWS SecretsManager endpoints have the following
	// schema:
	//  secrestmanager[-fips].<region>.amanzonaws.com
	Endpoint Env[string]

	// Region is the AWS region the SecretsManager is
	// located.
	Region Env[string]

	// KMSKey is the AWS-KMS key ID (CMK-ID) used to
	// to en/decrypt secrets managed by the SecretsManager.
	// If empty, the default AWS KMS key is used.
	KMSKey Env[string]

	// AccessKey is the access key for authenticating to AWS.
	AccessKey Env[string]

	// SecretKey is the secret key for authenticating to AWS.
	SecretKey Env[string]

	// SessionToken is an optional session token for authenticating
	// to AWS.
	SessionToken Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the AWS SecretsManager.
func (c *SecretsManagerConfig) Connect(ctx context.Context) (kms.Conn, error) {
	return aws.Connect(ctx, &aws.Config{
		Addr:     c.Endpoint.Value,
		Region:   c.Region.Value,
		KMSKeyID: c.KMSKey.Value,
		Login: aws.Credentials{
			AccessKey:    c.AccessKey.Value,
			SecretKey:    c.SecretKey.Value,
			SessionToken: c.SessionToken.Value,
		},
	})
}

func (c *SecretsManagerConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Aws.SecretsManager.Endpoint = c.Endpoint
	yml.KeyStore.Aws.SecretsManager.Region = c.Region
	yml.KeyStore.Aws.SecretsManager.KmsKey = c.KMSKey
	yml.KeyStore.Aws.SecretsManager.Login.AccessKey = c.AccessKey
	yml.KeyStore.Aws.SecretsManager.Login.SecretKey = c.SecretKey
	yml.KeyStore.Aws.SecretsManager.Login.SessionToken = c.SessionToken
}

func (c *SecretsManagerConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Aws.SecretsManager.Endpoint
	c.Region = yml.KeyStore.Aws.SecretsManager.Region
	c.KMSKey = yml.KeyStore.Aws.SecretsManager.KmsKey
	c.AccessKey = yml.KeyStore.Aws.SecretsManager.Login.AccessKey
	c.SecretKey = yml.KeyStore.Aws.SecretsManager.Login.SecretKey
	c.SessionToken = yml.KeyStore.Aws.SecretsManager.Login.SessionToken
}

// SecretManagerConfig is a structure containing the
// configuration for GCP SecretManager.
type SecretManagerConfig struct {
	// ProjectID is the GCP project ID.
	ProjectID Env[string]

	// Endpoint is the GCP project ID. If empty,
	// defaults to:
	//   secretmanager.googleapis.com:443
	Endpoint Env[string]

	// Scopes are GCP OAuth2 scopes for accessing
	// GCP APIs. If empty, defaults to the GCP
	// default scopes.
	Scopes []Env[string]

	// ClientEmail is the Client email of the
	// GCP service account used to access the
	// SecretManager.
	ClientEmail Env[string]

	// ClientID is the Client ID of the GCP
	// service account used to access the
	// SecretManager.
	ClientID Env[string]

	// KeyID is the private key ID of the GCP
	// service account used to access the
	// SecretManager.
	KeyID Env[string]

	// Key is the private key of the GCP
	// service account used to access the
	// SecretManager.
	Key Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the GCP SecretManager.
func (c *SecretManagerConfig) Connect(ctx context.Context) (kms.Conn, error) {
	config := &gcp.Config{
		Endpoint:  c.Endpoint.Value,
		ProjectID: c.ProjectID.Value,
		Credentials: gcp.Credentials{
			ClientID: c.ClientID.Value,
			Client:   c.ClientEmail.Value,
			KeyID:    c.KeyID.Value,
			Key:      c.Key.Value,
		},
	}
	for _, scope := range c.Scopes {
		config.Scopes = append(config.Scopes, scope.Value)
	}
	return gcp.Connect(ctx, config)
}

func (c *SecretManagerConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.GCP.SecretManager.ProjectID = c.ProjectID
	yml.KeyStore.GCP.SecretManager.Endpoint = c.Endpoint
	yml.KeyStore.GCP.SecretManager.Scopes = c.Scopes
	yml.KeyStore.GCP.SecretManager.Credentials.Client = c.ClientEmail
	yml.KeyStore.GCP.SecretManager.Credentials.ClientID = c.ClientID
	yml.KeyStore.GCP.SecretManager.Credentials.KeyID = c.KeyID
	yml.KeyStore.GCP.SecretManager.Credentials.Key = c.Key
}

func (c *SecretManagerConfig) fromYAML(yml *serverConfigYAML) {
	c.ProjectID = yml.KeyStore.GCP.SecretManager.ProjectID
	c.Endpoint = yml.KeyStore.GCP.SecretManager.Endpoint
	c.Scopes = yml.KeyStore.GCP.SecretManager.Scopes
	c.ClientEmail = yml.KeyStore.GCP.SecretManager.Credentials.Client
	c.ClientID = yml.KeyStore.GCP.SecretManager.Credentials.ClientID
	c.KeyID = yml.KeyStore.GCP.SecretManager.Credentials.KeyID
	c.Key = yml.KeyStore.GCP.SecretManager.Credentials.Key
}

// KeyVaultConfig is a structure containing the
// configuration for Azure KeyVault.
type KeyVaultConfig struct {
	// Endpoint is the Azure KeyVault endpoint.
	Endpoint Env[string]

	// TenantID is the ID of the Azure KeyVault tenant.
	TenantID Env[string]

	// ClientID is the ID of the client accessing
	// Azure KeyVault.
	ClientID Env[string]

	// ClientSecret is the client secret accessing the
	// Azure KeyVault.
	ClientSecret Env[string]

	// ManagedIdentityClientID is the client ID of the
	// Azure managed identity that access the KeyVault.
	ManagedIdentityClientID Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the Azure KeyVault.
func (c *KeyVaultConfig) Connect(ctx context.Context) (kms.Conn, error) {
	if (c.TenantID.Value != "" || c.ClientID.Value != "" || c.ClientSecret.Value != "") && c.ManagedIdentityClientID.Value != "" {
		return nil, errors.New("") // TODO
	}
	switch {
	case c.TenantID.Value != "" || c.ClientID.Value != "" || c.ClientSecret.Value != "":
		creds := azure.Credentials{
			TenantID: c.Endpoint.Value,
			ClientID: c.ClientID.Value,
			Secret:   c.ClientSecret.Value,
		}
		return azure.ConnectWithCredentials(ctx, c.Endpoint.Value, creds)
	case c.ManagedIdentityClientID.Value != "":
		creds := azure.ManagedIdentity{
			ClientID: c.ManagedIdentityClientID.Value,
		}
		return azure.ConnectWithIdentity(ctx, c.Endpoint.Value, creds)
	default:
		return nil, errors.New("") // TODO
	}
}

func (c *KeyVaultConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Azure.KeyVault.Endpoint = c.Endpoint
	yml.KeyStore.Azure.KeyVault.Credentials.TenantID = c.TenantID
	yml.KeyStore.Azure.KeyVault.Credentials.ClientID = c.ClientID
	yml.KeyStore.Azure.KeyVault.Credentials.Secret = c.ClientSecret
	yml.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID = c.ManagedIdentityClientID
}

func (c *KeyVaultConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Azure.KeyVault.Endpoint
	c.TenantID = yml.KeyStore.Azure.KeyVault.Credentials.TenantID
	c.ClientID = yml.KeyStore.Azure.KeyVault.Credentials.ClientID
	c.ClientSecret = yml.KeyStore.Azure.KeyVault.Credentials.Secret
	c.ManagedIdentityClientID = yml.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID
}

// KeySecureConfig is a structure containing the
// configuration for Gemalto KeySecure / Thales
// CipherTrust Manager.
type KeySecureConfig struct {
	// Endpoint is the endpoint to the KeySecure server.
	Endpoint Env[string]

	// Token is the refresh authentication token to
	// access the KeySecure server.
	Token Env[string]

	// Domain is the isolated namespace within the
	// KeySecure server. If empty, defaults to the
	// top-level / root domain.
	Domain Env[string]

	// Retry is the retry delay between authentication attempts.
	// If not set, defaults to 15s.
	Retry Env[time.Duration]

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KeySecure server.
	//
	// If empty, the OS default root CA set is
	// used.
	CAPath Env[string]

	_ [0]int
}

// Connect establishes and returns a kms.Conn to the KeySecure server.
func (c *KeySecureConfig) Connect(ctx context.Context) (kms.Conn, error) {
	return gemalto.Connect(ctx, &gemalto.Config{
		Endpoint: c.Endpoint.Value,
		CAPath:   c.CAPath.Value,
		Login: gemalto.Credentials{
			Token:  c.Token.Value,
			Domain: c.Domain.Value,
			Retry:  c.Retry.Value,
		},
	})
}

func (c *KeySecureConfig) toYAML(yml *serverConfigYAML) {
	yml.KeyStore.Gemalto.KeySecure.Endpoint = c.Endpoint
	yml.KeyStore.Gemalto.KeySecure.Login.Token = c.Token
	yml.KeyStore.Gemalto.KeySecure.Login.Domain = c.Domain
	yml.KeyStore.Gemalto.KeySecure.Login.Retry = c.Retry
	yml.KeyStore.Gemalto.KeySecure.TLS.CAPath = c.CAPath
}

func (c *KeySecureConfig) fromYAML(yml *serverConfigYAML) {
	c.Endpoint = yml.KeyStore.Gemalto.KeySecure.Endpoint
	c.Token = yml.KeyStore.Gemalto.KeySecure.Login.Token
	c.Domain = yml.KeyStore.Gemalto.KeySecure.Login.Domain
	c.Retry = yml.KeyStore.Gemalto.KeySecure.Login.Retry
	c.CAPath = yml.KeyStore.Gemalto.KeySecure.TLS.CAPath
}
