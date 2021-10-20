// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	"github.com/minio/kes/internal/yml"
	"gopkg.in/yaml.v2"
)

// connect tries to establish a connection to the KMS specified in the ServerConfig
func connect(config *yml.ServerConfig, quiet quiet, errorLog *stdlog.Logger) (key.Store, error) {
	switch {
	case config.KeyStore.Fs.Path.Value() != "":
		f, err := os.Stat(config.KeyStore.Fs.Path.Value())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to open %q: %v", config.KeyStore.Fs.Path.Value(), err)
		}
		if err == nil && !f.IsDir() {
			return nil, fmt.Errorf("%q is not a directory", config.KeyStore.Fs.Path.Value())
		}
		if errors.Is(err, os.ErrNotExist) {
			msg := fmt.Sprintf("Creating directory '%s' ... ", config.KeyStore.Fs.Path.Value())
			quiet.Print(msg)
			if err = os.MkdirAll(config.KeyStore.Fs.Path.Value(), 0700); err != nil {
				return nil, fmt.Errorf("failed to create directory %q: %v", config.KeyStore.Fs.Path.Value(), err)
			}
			quiet.ClearMessage(msg)
		}
		return &fs.Store{
			Dir:      config.KeyStore.Fs.Path.Value(),
			ErrorLog: errorLog,
		}, nil
	case config.KeyStore.Generic.Endpoint.Value() != "":
		genericStore := &generic.Store{
			Endpoint: config.KeyStore.Generic.Endpoint.Value(),
			KeyPath:  config.KeyStore.Generic.TLS.PrivateKey.Value(),
			CertPath: config.KeyStore.Generic.TLS.Certificate.Value(),
			CAPath:   config.KeyStore.Generic.TLS.CAPath.Value(),
			ErrorLog: errorLog,
		}
		msg := fmt.Sprintf("Authenticating to generic KeyStore '%s' ... ", config.KeyStore.Generic.Endpoint.Value())
		quiet.Print(msg)
		if err := genericStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to generic KeyStore: %v", err)
		}
		quiet.ClearMessage(msg)
		return genericStore, nil
	case config.KeyStore.Vault.Endpoint.Value() != "":
		msg := fmt.Sprintf("Authenticating to Hashicorp Vault '%s' ... ", config.KeyStore.Vault.Endpoint.Value())
		quiet.Print(msg)
		vaultStore, err := vault.Connect(context.Background(), &vault.Config{
			Endpoint:   config.KeyStore.Vault.Endpoint.Value(),
			Engine:     config.KeyStore.Vault.Engine.Value(),
			APIVersion: config.KeyStore.Vault.APIVersion.Value(),
			Prefix:     config.KeyStore.Vault.Prefix.Value(),
			Namespace:  config.KeyStore.Vault.Namespace.Value(),
			AppRole: vault.AppRole{
				Engine: config.KeyStore.Vault.AppRole.Engine.Value(),
				ID:     config.KeyStore.Vault.AppRole.ID.Value(),
				Secret: config.KeyStore.Vault.AppRole.Secret.Value(),
				Retry:  config.KeyStore.Vault.AppRole.Retry.Value(),
			},
			K8S: vault.Kubernetes{
				Engine: config.KeyStore.Vault.Kubernetes.Engine.Value(),
				Role:   config.KeyStore.Vault.Kubernetes.Role.Value(),
				JWT:    config.KeyStore.Vault.Kubernetes.JWT.Value(),
				Retry:  config.KeyStore.Vault.Kubernetes.Retry.Value(),
			},
			StatusPingAfter: config.KeyStore.Vault.Status.Ping.Value(),
			ErrorLog:        errorLog,
			ClientKeyPath:   config.KeyStore.Vault.TLS.PrivateKey.Value(),
			ClientCertPath:  config.KeyStore.Vault.TLS.Certificate.Value(),
			CAPath:          config.KeyStore.Vault.TLS.CAPath.Value(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Vault: %v", err)
		}
		quiet.ClearMessage(msg)
		return vaultStore, nil
	case config.KeyStore.Fortanix.SDKMS.Endpoint.Value() != "":
		fortanixStore := &fortanix.KeyStore{
			Endpoint: config.KeyStore.Fortanix.SDKMS.Endpoint.Value(),
			GroupID:  config.KeyStore.Fortanix.SDKMS.GroupID.Value(),
			APIKey:   fortanix.APIKey(config.KeyStore.Fortanix.SDKMS.Login.APIKey.Value()),
			ErrorLog: errorLog,
			CAPath:   config.KeyStore.Fortanix.SDKMS.TLS.CAPath.Value(),
		}
		msg := fmt.Sprintf("Authenticating to Fortanix SDKMS '%s' ... ", fortanixStore.Endpoint)
		quiet.Print(msg)
		if err := fortanixStore.Authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to connect to Fortanix SDKMS: %v", err)
		}
		quiet.ClearMessage(msg)
		return fortanixStore, nil
	case config.KeyStore.Aws.SecretsManager.Endpoint.Value() != "":
		awsStore := &aws.SecretsManager{
			Addr:     config.KeyStore.Aws.SecretsManager.Endpoint.Value(),
			Region:   config.KeyStore.Aws.SecretsManager.Region.Value(),
			KMSKeyID: config.KeyStore.Aws.SecretsManager.KmsKey.Value(),
			ErrorLog: errorLog,
			Login: aws.Credentials{
				AccessKey:    config.KeyStore.Aws.SecretsManager.Login.AccessKey.Value(),
				SecretKey:    config.KeyStore.Aws.SecretsManager.Login.SecretKey.Value(),
				SessionToken: config.KeyStore.Aws.SecretsManager.Login.SessionToken.Value(),
			},
		}

		msg := fmt.Sprintf("Authenticating to AWS SecretsManager '%s' ... ", awsStore.Addr)
		quiet.Print(msg)
		if err := awsStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to AWS Secrets Manager: %v", err)
		}
		quiet.ClearMessage(msg)
		return awsStore, nil
	case config.KeyStore.GCP.SecretManager.ProjectID.Value() != "":
		msg := fmt.Sprintf("Authenticating to GCP SecretManager Project: '%s' ... ", config.KeyStore.GCP.SecretManager.ProjectID.Value())
		quiet.Print(msg)
		gcpStore, err := gcp.Connect(context.Background(), &gcp.Config{
			Endpoint:  config.KeyStore.GCP.SecretManager.Endpoint.Value(),
			ProjectID: config.KeyStore.GCP.SecretManager.ProjectID.Value(),
			Credentials: gcp.Credentials{
				ClientID: config.KeyStore.GCP.SecretManager.Credentials.ClientID.Value(),
				Client:   config.KeyStore.GCP.SecretManager.Credentials.Client.Value(),
				KeyID:    config.KeyStore.GCP.SecretManager.Credentials.KeyID.Value(),
				Key:      config.KeyStore.GCP.SecretManager.Credentials.Key.Value(),
			},
			ErrorLog: errorLog,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to GCP SecretManager: %v", err)
		}
		quiet.ClearMessage(msg)
		return gcpStore, nil
	case config.KeyStore.Azure.KeyVault.Endpoint.Value() != "":
		azureStore := &azure.KeyVault{
			Endpoint: config.KeyStore.Azure.KeyVault.Endpoint.Value(),
			ErrorLog: errorLog,
		}
		msg := fmt.Sprintf("Authenticating to Azure KeyVault '%s' ... ", config.KeyStore.Azure.KeyVault.Endpoint)
		quiet.Print(msg)
		switch c := config.KeyStore.Azure.KeyVault.Credentials; {
		case c.TenantID.Value() != "" || c.ClientID.Value() != "" || c.Secret.Value() != "":
			var err = azureStore.AuthenticateWithCredentials(azure.Credentials{
				TenantID: config.KeyStore.Azure.KeyVault.Credentials.TenantID.Value(),
				ClientID: config.KeyStore.Azure.KeyVault.Credentials.ClientID.Value(),
				Secret:   config.KeyStore.Azure.KeyVault.Credentials.Secret.Value(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
			}
		case config.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value() != "":
			var err = azureStore.AuthenticateWithIdentity(azure.ManagedIdentity{
				ClientID: config.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
			}
		default:
			return nil, errors.New("failed to connect to Azure KeyVault: no client credentials or managed identity")
		}
		quiet.ClearMessage(msg)
		return azureStore, nil
	case config.KeyStore.Gemalto.KeySecure.Endpoint.Value() != "":
		gemaltoStore := &gemalto.KeySecure{
			Endpoint: config.KeyStore.Gemalto.KeySecure.Endpoint.Value(),
			CAPath:   config.KeyStore.Gemalto.KeySecure.TLS.CAPath.Value(),
			ErrorLog: errorLog,
			Login: gemalto.Credentials{
				Token:  config.KeyStore.Gemalto.KeySecure.Login.Token.Value(),
				Domain: config.KeyStore.Gemalto.KeySecure.Login.Domain.Value(),
				Retry:  config.KeyStore.Gemalto.KeySecure.Login.Retry.Value(),
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

func description(config *yml.ServerConfig) (kind, endpoint string, err error) {
	switch {
	case config.KeyStore.Fs.Path.Value() != "":
		kind = "Filesystem"
		if endpoint, err = filepath.Abs(config.KeyStore.Fs.Path.Value()); err != nil {
			endpoint = config.KeyStore.Fs.Path.Value()
		}
	case config.KeyStore.Generic.Endpoint.Value() != "":
		kind = "Generic"
		endpoint = config.KeyStore.Generic.Endpoint.Value()
	case config.KeyStore.Vault.Endpoint.Value() != "":
		kind = "Hashicorp Vault"
		endpoint = config.KeyStore.Vault.Endpoint.Value()
	case config.KeyStore.Fortanix.SDKMS.Endpoint.Value() != "":
		kind = "Fortanix SDKMS"
		endpoint = config.KeyStore.Fortanix.SDKMS.Endpoint.Value()
	case config.KeyStore.Aws.SecretsManager.Endpoint.Value() != "":
		kind = "AWS SecretsManager"
		endpoint = config.KeyStore.Aws.SecretsManager.Endpoint.Value()
	case config.KeyStore.Gemalto.KeySecure.Endpoint.Value() != "":
		kind = "Gemalto KeySecure"
		endpoint = config.KeyStore.Gemalto.KeySecure.Endpoint.Value()
	case config.KeyStore.GCP.SecretManager.ProjectID.Value() != "":
		kind = "GCP SecretManager"
		endpoint = config.KeyStore.GCP.SecretManager.Endpoint.Value() + " | Project: " + config.KeyStore.GCP.SecretManager.ProjectID.Value()
	case config.KeyStore.Azure.KeyVault.Endpoint.Value() != "":
		kind = "Azure KeyVault"
		endpoint = config.KeyStore.Azure.KeyVault.Endpoint.Value()
	default:
		kind = "In-Memory"
		endpoint = "non-persistent"
	}
	return kind, endpoint, nil
}

// expandEnv replaces s with a value from the environment if
// s refers to an environment variable. If the referenced
// environment variable does not exist s gets replaced with
// the empty string.
//
// s refers to an environment variable if it has the following
// form: ${<name>}.
//
// If s does not refer to an environment variable then s is
// returned unmodified.
func expandEnv(s string) string {
	if t := strings.TrimSpace(s); strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}") {
		return os.ExpandEnv(t)
	}
	return s
}

// duration is an alias for time.Duration that
// implements YAML unmarshaling by first replacing
// any reference to an environment variable ${...}
// with the referenced value.
type duration time.Duration

var (
	_ yaml.Marshaler   = duration(0)
	_ yaml.Unmarshaler = (*duration)(nil)
)

func (d duration) MarshalYAML() (interface{}, error) { return time.Duration(d).String(), nil }

func (d *duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	v, err := time.ParseDuration(expandEnv(s))
	if err != nil {
		return err
	}
	*d = duration(v)
	return nil
}
