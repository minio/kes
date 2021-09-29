// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/aws"
	"github.com/minio/kes/internal/azure"
	"github.com/minio/kes/internal/fortanix"
	"github.com/minio/kes/internal/fs"
	"github.com/minio/kes/internal/gcp"
	"github.com/minio/kes/internal/gemalto"
	"github.com/minio/kes/internal/generic"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/vault"
	"gopkg.in/yaml.v2"
)

// GatewayConfig is the KES gateway configuration.
type GatewayConfig struct {
	Addr string       `yaml:"address"`
	Root kes.Identity `yaml:"root"`

	TLS struct {
		KeyPath  string `yaml:"key"`
		CertPath string `yaml:"cert"`
		Proxy    struct {
			Identities []kes.Identity `yaml:"identities"`
			Header     struct {
				ClientCert string `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`
	} `yaml:"tls"`

	Policies map[string]policyConfig `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any    duration `yaml:"any"`    // Use custom type for env. var support
			Unused duration `yaml:"unused"` // Use custom type for env. var support
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error string `yaml:"error"`
		Audit string `yaml:"audit"`
	} `yaml:"log"`

	Keys []struct {
		Name string `yaml:"name"`
	} `yaml:"keys"`

	KeyStore KeyStoreConfig `yaml:"keystore"`
}

// GatewayConfigFromFile reads the KES gateway configuration
// form the given file.
//
// It replaces any environment variable references in the
// configuration with values fetched from the environment.
//
// GatewayConfigFromFile does set some default configuration
// values if not present resp. empty in the configuration
// file.
func GatewayConfigFromFile(filePath string) (GatewayConfig, error) {
	b, err := ioutil.ReadFile(filePath)
	if err != nil {
		return GatewayConfig{}, err
	}

	var config GatewayConfig
	if err = yaml.Unmarshal(b, &config); err != nil {
		return GatewayConfig{}, err
	}

	// Replace any configuration file fields that refer to env. variables
	// with the corresponding env. variable value.
	// A field refers to an env. variable if it has the form:
	//   ${<env-var-name>}
	//
	// We have to replace fields that refer to env. variables before we
	// do anything else (e.g. verify that the config file is well-formed)
	// since we have to take values coming from the env. into account.
	//
	// We don't replace any policy paths. Replacing policy paths is quite
	// dangerous since it would not be obvious which operations are allowed
	// by a policy.
	config.Addr = expandEnv(config.Addr)
	config.Root = kes.Identity(expandEnv(config.Root.String()))

	config.TLS.KeyPath = expandEnv(config.TLS.KeyPath)
	config.TLS.CertPath = expandEnv(config.TLS.CertPath)
	config.TLS.Proxy.Header.ClientCert = expandEnv(config.TLS.Proxy.Header.ClientCert)
	for i, identity := range config.TLS.Proxy.Identities { // The TLS proxy identities section
		config.TLS.Proxy.Identities[i] = kes.Identity(expandEnv(identity.String()))
	}

	config.Log.Audit = expandEnv(config.Log.Audit)
	config.Log.Error = os.ExpandEnv(config.Log.Error)

	for _, policy := range config.Policies { // The policy section
		for i, identity := range policy.Identities {
			policy.Identities[i] = kes.Identity(expandEnv(identity.String()))
		}
	}

	for i, key := range config.Keys {
		config.Keys[i].Name = expandEnv(key.Name)
	}

	config.setDefaults()
	if err = config.verify(); err != nil {
		return GatewayConfig{}, err
	}
	return config, nil
}

// setDefaults set default values for fields that may be empty since not specified by user.
func (c *GatewayConfig) setDefaults() {
	if c.Cache.Expiry.Any == 0 {
		c.Cache.Expiry.Any = duration(5 * time.Minute)
	}
	if c.Cache.Expiry.Unused == 0 {
		c.Cache.Expiry.Unused = duration(30 * time.Second)
	}
	if c.Log.Audit == "" {
		c.Log.Audit = "off" // If not set, default is off.
	}
	if c.Log.Error == "" {
		c.Log.Error = "on" // If not set, default is on.
	}
	c.KeyStore.setDefaults()
}

// verify returns an error if the GatewayConfig contains invalid or
// ambigious values.
func (c *GatewayConfig) verify() error {
	if c.Root.IsUnknown() {
		return errors.New("no root identity has been specified")
	}
	if c.TLS.KeyPath == "" {
		return errors.New("no private key file has been specified")
	}
	if c.TLS.CertPath == "" {
		return errors.New("no certificate file has been specified")
	}

	for i, identity := range c.TLS.Proxy.Identities {
		if identity == c.Root {
			return fmt.Errorf("The %d-th TLS proxy identity is equal to the root identity %q. The root identity cannot be used as TLS proxy", i, identity)
		}
	}

	if v := strings.ToLower(c.Log.Audit); v != "on" && v != "off" {
		return fmt.Errorf("%q is an invalid audit log configuration", v)
	}
	if v := strings.ToLower(c.Log.Error); v != "on" && v != "off" {
		return fmt.Errorf("%q is an invalid error log configuration", v)
	}
	return c.KeyStore.verify()
}

// KeyStoreConfig is the KES gateway keystore backend configuration.
type KeyStoreConfig struct {
	Fs struct {
		Path string `yaml:"path"`
	} `yaml:"fs"`

	Generic struct {
		Endpoint string `yaml:"endpoint"`
		TLS      struct {
			KeyPath  string `yaml:"key"`
			CertPath string `yaml:"cert"`
			CAPath   string `yaml:"ca"`
		} `yaml:"tls"`
	} `yaml:"generic"`

	Vault struct {
		Endpoint      string `yaml:"endpoint"`
		EnginePath    string `yaml:"engine"`
		EngineVersion string `yaml:"version"`
		Namespace     string `yaml:"namespace"`

		Prefix string `yaml:"prefix"`

		AppRole struct {
			EnginePath string   `yaml:"engine"`
			ID         string   `yaml:"id"`
			Secret     string   `yaml:"secret"`
			Retry      duration `yaml:"retry"` // Use custom type for env. var support
		} `yaml:"approle"`

		Kubernetes struct {
			EnginePath string   `yaml:"engine"`
			Role       string   `yaml:"role"`
			JWT        string   `yaml:"jwt"`   // Can be either a JWT or a path to a file containing a JWT
			Retry      duration `yaml:"retry"` // Use custom type for env. var support
		} `yaml:"kubernetes"`

		TLS struct {
			KeyPath  string `yaml:"key"`
			CertPath string `yaml:"cert"`
			CAPath   string `yaml:"ca"`
		} `yaml:"tls"`

		Status struct {
			Ping duration `yaml:"ping"` // Use custom type for env. var support
		} `yaml:"status"`
	} `yaml:"vault"`

	Fortanix struct {
		SDKMS struct {
			Endpoint string `yaml:"endpoint"`
			GroupID  string `yaml:"group_id"`

			Login struct {
				APIKey string `yaml:"key"`
			} `yaml:"credentials"`

			TLS struct {
				CAPath string `yaml:"ca"`
			} `yaml:"tls"`
		} `yaml:"sdkms"`
	} `yaml:"fortanix"`

	Aws struct {
		SecretsManager struct {
			Endpoint string `yaml:"endpoint"`
			Region   string `yaml:"region"`
			KmsKey   string ` yaml:"kmskey"`

			Login struct {
				AccessKey    string `yaml:"accesskey"`
				SecretKey    string `yaml:"secretkey"`
				SessionToken string `yaml:"token"`
			} `yaml:"credentials"`
		} `yaml:"secretsmanager"`
	} `yaml:"aws"`

	GCP struct {
		SecretManager struct {
			ProjectID   string `yaml:"project_id"`
			Endpoint    string `yaml:"endpoint"`
			Credentials struct {
				Client   string `yaml:"client_email"`
				ClientID string `yaml:"client_id"`
				KeyID    string `yaml:"private_key_id"`
				Key      string `yaml:"private_key"`
			} `yaml:"credentials"`
		} `yaml:"secretmanager"`
	} `yaml:"gcp"`

	Azure struct {
		KeyVault struct {
			Endpoint    string `yaml:"endpoint"`
			Credentials struct {
				TenantID string `yaml:"tenant_id"`
				ClientID string `yaml:"client_id"`
				Secret   string `yaml:"client_secret"`
			}
		} `yaml:"keyvault"`
	} `yaml:"azure"`

	Gemalto struct {
		KeySecure struct {
			Endpoint string `yaml:"endpoint"`

			Login struct {
				Token  string   `yaml:"token"`
				Domain string   `yaml:"domain"`
				Retry  duration `yaml:"retry"` // Use custom type for env. var support
			} `yaml:"credentials"`

			TLS struct {
				CAPath string `yaml:"ca"`
			} `yaml:"tls"`
		} `yaml:"keysecure"`
	} `yaml:"gemalto"`
}

// Connect tries to establish a connection to the KMS specified in the kmsServerConfig.
func (c *KeyStoreConfig) Connect(quiet quiet, errorLog *stdlog.Logger) (key.Store, error) {
	switch {
	case c.Fs.Path != "":
		f, err := os.Stat(c.Fs.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to open %q: %v", c.Fs.Path, err)
		}
		if err == nil && !f.IsDir() {
			return nil, fmt.Errorf("%q is not a directory", c.Fs.Path)
		}
		if errors.Is(err, os.ErrNotExist) {
			msg := fmt.Sprintf("Creating directory '%s' ... ", c.Fs.Path)
			quiet.Print(msg)
			if err = os.MkdirAll(c.Fs.Path, 0700); err != nil {
				return nil, fmt.Errorf("failed to create directory %q: %v", c.Fs.Path, err)
			}
			quiet.ClearMessage(msg)
		}
		return &fs.Store{
			Dir:      c.Fs.Path,
			ErrorLog: errorLog,
		}, nil
	case c.Generic.Endpoint != "":
		genericStore := &generic.Store{
			Endpoint: c.Generic.Endpoint,
			KeyPath:  c.Generic.TLS.KeyPath,
			CertPath: c.Generic.TLS.CertPath,
			CAPath:   c.Generic.TLS.CAPath,
			ErrorLog: errorLog,
		}
		msg := fmt.Sprintf("Authenticating to generic KeyStore '%s' ... ", c.Generic.Endpoint)
		quiet.Print(msg)
		if err := genericStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to generic KeyStore: %v", err)
		}
		quiet.ClearMessage(msg)
		return genericStore, nil
	case c.Vault.Endpoint != "":
		vaultStore := &vault.Store{
			Addr:          c.Vault.Endpoint,
			Engine:        c.Vault.EnginePath,
			EngineVersion: c.Vault.EngineVersion,
			Location:      c.Vault.Prefix,
			Namespace:     c.Vault.Namespace,
			AppRole: vault.AppRole{
				Engine: c.Vault.AppRole.EnginePath,
				ID:     c.Vault.AppRole.ID,
				Secret: c.Vault.AppRole.Secret,
				Retry:  time.Duration(c.Vault.AppRole.Retry),
			},
			K8S: vault.Kubernetes{
				Engine: c.Vault.Kubernetes.EnginePath,
				Role:   c.Vault.Kubernetes.Role,
				JWT:    c.Vault.Kubernetes.JWT,
				Retry:  time.Duration(c.Vault.Kubernetes.Retry),
			},
			StatusPingAfter: time.Duration(c.Vault.Status.Ping),
			ErrorLog:        errorLog,
			ClientKeyPath:   c.Vault.TLS.KeyPath,
			ClientCertPath:  c.Vault.TLS.CertPath,
			CAPath:          c.Vault.TLS.CAPath,
		}

		msg := fmt.Sprintf("Authenticating to Hashicorp Vault '%s' ... ", vaultStore.Addr)
		quiet.Print(msg)
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to connect to Vault: %v", err)
		}
		quiet.ClearMessage(msg)
		return vaultStore, nil
	case c.Fortanix.SDKMS.Endpoint != "":
		fortanixStore := &fortanix.KeyStore{
			Endpoint: c.Fortanix.SDKMS.Endpoint,
			GroupID:  c.Fortanix.SDKMS.GroupID,
			APIKey:   fortanix.APIKey(c.Fortanix.SDKMS.Login.APIKey),
			ErrorLog: errorLog,
			CAPath:   c.Fortanix.SDKMS.TLS.CAPath,
		}
		msg := fmt.Sprintf("Authenticating to Fortanix SDKMS '%s' ... ", fortanixStore.Endpoint)
		quiet.Print(msg)
		if err := fortanixStore.Authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to connect to Fortanix SDKMS: %v", err)
		}
		quiet.ClearMessage(msg)
		return fortanixStore, nil
	case c.Aws.SecretsManager.Endpoint != "":
		awsStore := &aws.SecretsManager{
			Addr:     c.Aws.SecretsManager.Endpoint,
			Region:   c.Aws.SecretsManager.Region,
			KMSKeyID: c.Aws.SecretsManager.KmsKey,
			ErrorLog: errorLog,
			Login: aws.Credentials{
				AccessKey:    c.Aws.SecretsManager.Login.AccessKey,
				SecretKey:    c.Aws.SecretsManager.Login.SecretKey,
				SessionToken: c.Aws.SecretsManager.Login.SessionToken,
			},
		}

		msg := fmt.Sprintf("Authenticating to AWS SecretsManager '%s' ... ", awsStore.Addr)
		quiet.Print(msg)
		if err := awsStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to AWS Secrets Manager: %v", err)
		}
		quiet.ClearMessage(msg)
		return awsStore, nil
	case c.GCP.SecretManager.ProjectID != "":
		gcpStore := &gcp.SecretManager{
			Endpoint:  c.GCP.SecretManager.Endpoint,
			ProjectID: c.GCP.SecretManager.ProjectID,
			ErrorLog:  errorLog,
		}

		msg := fmt.Sprintf("Authenticating to GCP SecretManager Project: '%s' ... ", gcpStore.ProjectID)
		quiet.Print(msg)
		err := gcpStore.Authenticate(gcp.Credentials{
			ClientID: c.GCP.SecretManager.Credentials.ClientID,
			Client:   c.GCP.SecretManager.Credentials.Client,
			KeyID:    c.GCP.SecretManager.Credentials.KeyID,
			Key:      c.GCP.SecretManager.Credentials.Key,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to GCP SecretManager: %v", err)
		}
		quiet.ClearMessage(msg)
		return gcpStore, nil
	case c.Azure.KeyVault.Endpoint != "":
		azureStore := &azure.KeyVault{
			Endpoint: c.Azure.KeyVault.Endpoint,
			ErrorLog: errorLog,
		}
		msg := fmt.Sprintf("Authenticating to Azure KeyVault '%s' ... ", c.Azure.KeyVault.Endpoint)
		quiet.Print(msg)
		err := azureStore.Authenticate(azure.Credentials{
			TenantID: c.Azure.KeyVault.Credentials.TenantID,
			ClientID: c.Azure.KeyVault.Credentials.ClientID,
			Secret:   c.Azure.KeyVault.Credentials.Secret,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
		}
		quiet.ClearMessage(msg)
		return azureStore, nil
	case c.Gemalto.KeySecure.Endpoint != "":
		gemaltoStore := &gemalto.KeySecure{
			Endpoint: c.Gemalto.KeySecure.Endpoint,
			CAPath:   c.Gemalto.KeySecure.TLS.CAPath,
			ErrorLog: errorLog,
			Login: gemalto.Credentials{
				Token:  c.Gemalto.KeySecure.Login.Token,
				Domain: c.Gemalto.KeySecure.Login.Domain,
				Retry:  time.Duration(c.Gemalto.KeySecure.Login.Retry),
			},
		}

		msg := fmt.Sprintf("Authenticating to Gemalto KeySecure '%s' ... ", gemaltoStore.Endpoint)
		quiet.Print(msg)
		if err := gemaltoStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to Gemalto KeySecure: %v", err)
		}
		quiet.ClearMessage(msg)
		return gemaltoStore, nil
	default:
		return &mem.Store{}, nil
	}
}

// Description returns the KES gateway keystore backend kind
// and the corresponding endpoint.
func (c *KeyStoreConfig) Description() (kind, endpoint string) {
	switch {
	case c.Fs.Path != "":
		kind = "Filesystem"

		var err error
		if endpoint, err = filepath.Abs(c.Fs.Path); err != nil {
			endpoint = c.Fs.Path
		}
	case c.Generic.Endpoint != "":
		kind = "Generic"
		endpoint = c.Generic.Endpoint
	case c.Vault.Endpoint != "":
		kind = "Hashicorp Vault"
		endpoint = c.Vault.Endpoint
	case c.Fortanix.SDKMS.Endpoint != "":
		kind = "Fortanix SDKMS"
		endpoint = c.Fortanix.SDKMS.Endpoint
	case c.Aws.SecretsManager.Endpoint != "":
		kind = "AWS SecretsManager"
		endpoint = c.Aws.SecretsManager.Endpoint
	case c.Gemalto.KeySecure.Endpoint != "":
		kind = "Gemalto KeySecure"
		endpoint = c.Gemalto.KeySecure.Endpoint
	case c.GCP.SecretManager.ProjectID != "":
		kind = "GCP SecretManager"
		endpoint = c.GCP.SecretManager.Endpoint + " | Project: " + c.GCP.SecretManager.ProjectID
	case c.Azure.KeyVault.Endpoint != "":
		kind = "Azure KeyVault"
		endpoint = c.Azure.KeyVault.Endpoint
	default:
		kind = "In-Memory"
		endpoint = "non-persistent"
	}
	return kind, endpoint
}

// setDefaults set default values for fields that may be empty since not specified by user.
func (c *KeyStoreConfig) setDefaults() {
	if c.Vault.EnginePath == "" {
		c.Vault.EnginePath = "kv" // If not set, use the Vault default engine path.
	}
	if c.Vault.EngineVersion == "" {
		c.Vault.EngineVersion = vault.EngineV1
	}
	if c.Vault.AppRole.EnginePath == "" {
		c.Vault.AppRole.EnginePath = "approle" // If not set, use the Vault default auth path for AppRole.
	}
	if c.Vault.Kubernetes.EnginePath == "" {
		c.Vault.Kubernetes.EnginePath = "kubernetes" // If not set, use the Vault default auth path for Kubernetes.
	}
	if c.GCP.SecretManager.ProjectID != "" && c.GCP.SecretManager.Endpoint == "" {
		c.GCP.SecretManager.Endpoint = "secretmanager.googleapis.com:443"
	}
}

// verify returns an error if the KeyStoreConfig contains invalid or
// ambigious values.
//
// For example, it returns an error if two different backend endpoints
// are specified.
func (c *KeyStoreConfig) verify() error {
	// First, verify that the configuration is not ambiguous - i.e. multiple endpoints
	// are present.
	var endpoints = map[string]string{
		"FS":                 c.Fs.Path,
		"Generic":            c.Generic.Endpoint,
		"Hashicorp Vault":    c.Vault.Endpoint,
		"AWS SecretsManager": c.Aws.SecretsManager.Endpoint,
		"Gemalto KeySecure":  c.Gemalto.KeySecure.Endpoint,
		"GCP SecretManager":  c.GCP.SecretManager.ProjectID,
		"Azure KeyVault":     c.Azure.KeyVault.Endpoint,
		"Fortanix SDKMS":     c.Fortanix.SDKMS.Endpoint,
	}

	var Name string
	for name, endpoint := range endpoints {
		if Name != "" && endpoint != "" {
			return fmt.Errorf("ambiguous keystore configuration: %q and %q endpoint specified at the same time", Name, name)
		}
		if endpoint != "" {
			Name = name
		}
	}

	// For Hashicorp Vault we also verify that there is only one authentication method specified.
	if c.Vault.Endpoint != "" {
		approle, k8s := c.Vault.AppRole, c.Vault.Kubernetes
		if (approle.ID != "" || approle.Secret != "") && (k8s.Role != "" || k8s.JWT != "") {
			return errors.New("invalid keystore configuration: Vault AppRole and Kubernetes credentials are specified at the same time")
		}
	}
	return nil
}
