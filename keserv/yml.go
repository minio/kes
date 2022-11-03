// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keserv

import (
	"time"

	"github.com/minio/kes"
)

type serverConfigYAML struct {
	Addr Env[string] `yaml:"address,omitempty"`

	Admin struct {
		Identity Env[kes.Identity] `yaml:"identity"`
	} `yaml:"admin"`

	TLS struct {
		PrivateKey  Env[string] `yaml:"key"`
		Certificate Env[string] `yaml:"cert"`
		Password    Env[string] `yaml:"password,omitempty"`

		Proxy struct {
			Identities []Env[kes.Identity] `yaml:"identities,omitempty"`
			Header     struct {
				ClientCert Env[string] `yaml:"cert,omitempty"`
			} `yaml:"header,omitempty"`
		} `yaml:"proxy,omitempty"`
	} `yaml:"tls"`

	Policies map[string]struct {
		Allow      []string            `yaml:"allow,omitempty"`
		Deny       []string            `yaml:"deny,omitempty"`
		Identities []Env[kes.Identity] `yaml:"identities,omitempty"`
	} `yaml:"policy,omitempty"`

	Cache struct {
		Expiry struct {
			Any     Env[time.Duration] `yaml:"any,omitempty"`
			Unused  Env[time.Duration] `yaml:"unused,omitempty"`
			Offline Env[time.Duration] `yaml:"offline,omitempty"`
		} `yaml:"expiry,omitempty"`
	} `yaml:"cache,omitempty"`

	Log struct {
		Error Env[string] `yaml:"error,omitempty"`
		Audit Env[string] `yaml:"audit,omitempty"`
	} `yaml:"log,omitempty"`

	Keys []struct {
		Name Env[string] `yaml:"name,omitempty"`
	} `yaml:"keys,omitempty"`

	KeyStore struct {
		Fs struct {
			Path Env[string] `yaml:"path,omitempty"`
		} `yaml:"fs,omitempty"`

		Generic struct {
			Endpoint Env[string] `yaml:"endpoint,omitempty"`
			TLS      struct {
				PrivateKey  Env[string] `yaml:"key,omitempty"`
				Certificate Env[string] `yaml:"cert,omitempty"`
				CAPath      Env[string] `yaml:"ca,omitempty"`
			} `yaml:"tls,omitempty"`
		} `yaml:"generic,omitempty"`

		Vault struct {
			Endpoint   Env[string] `yaml:"endpoint,omitempty"`
			Engine     Env[string] `yaml:"engine,omitempty"`
			APIVersion Env[string] `yaml:"version,omitempty"`
			Namespace  Env[string] `yaml:"namespace,omitempty"`
			Prefix     Env[string] `yaml:"prefix,omitempty"`

			AppRole struct {
				Engine Env[string]        `yaml:"engine,omitempty"`
				ID     Env[string]        `yaml:"id,omitempty"`
				Secret Env[string]        `yaml:"secret,omitempty"`
				Retry  Env[time.Duration] `yaml:"retry,omitempty"`
			} `yaml:"approle,omitempty"`

			Kubernetes struct {
				Engine Env[string]        `yaml:"engine,omitempty"`
				Role   Env[string]        `yaml:"role,omitempty"`
				JWT    Env[string]        `yaml:"jwt,omitempty"` // Can be either a JWT or a path to a file containing a JWT
				Retry  Env[time.Duration] `yaml:"retry,omitempty"`
			} `yaml:"kubernetes,omitempty"`

			TLS struct {
				PrivateKey  Env[string] `yaml:"key,omitempty"`
				Certificate Env[string] `yaml:"cert,omitempty"`
				CAPath      Env[string] `yaml:"ca,omitempty"`
			} `yaml:"tls,omitempty"`

			Status struct {
				Ping Env[time.Duration] `yaml:"ping,omitempty"`
			} `yaml:"status,omitempty"`
		} `yaml:"vault,omitempty"`

		Fortanix struct {
			SDKMS struct {
				Endpoint Env[string] `yaml:"endpoint,omitempty"`
				GroupID  Env[string] `yaml:"group_id,omitempty"`

				Login struct {
					APIKey Env[string] `yaml:"key,omitempty"`
				} `yaml:"credentials,omitempty"`

				TLS struct {
					CAPath Env[string] `yaml:"ca,omitempty"`
				} `yaml:"tls,omitempty"`
			} `yaml:"sdkms,omitempty"`
		} `yaml:"fortanix,omitempty"`

		Aws struct {
			SecretsManager struct {
				Endpoint Env[string] `yaml:"endpoint,omitempty"`
				Region   Env[string] `yaml:"region,omitempty"`
				KmsKey   Env[string] ` yaml:"kmskey,omitempty"`

				Login struct {
					AccessKey    Env[string] `yaml:"accesskey,omitempty"`
					SecretKey    Env[string] `yaml:"secretkey,omitempty"`
					SessionToken Env[string] `yaml:"token,omitempty"`
				} `yaml:"credentials,omitempty"`
			} `yaml:"secretsmanager,omitempty"`
		} `yaml:"aws,omitempty"`

		GCP struct {
			SecretManager struct {
				ProjectID   Env[string]   `yaml:"project_id,omitempty"`
				Endpoint    Env[string]   `yaml:"endpoint,omitempty"`
				Scopes      []Env[string] `yaml:"scopes,omitempty"`
				Credentials struct {
					Client   Env[string] `yaml:"client_email,omitempty"`
					ClientID Env[string] `yaml:"client_id,omitempty"`
					KeyID    Env[string] `yaml:"private_key_id,omitempty"`
					Key      Env[string] `yaml:"private_key,omitempty"`
				} `yaml:"credentials,omitempty"`
			} `yaml:"secretmanager,omitempty"`
		} `yaml:"gcp,omitempty"`

		Azure struct {
			KeyVault struct {
				Endpoint    Env[string] `yaml:"endpoint,omitempty"`
				Credentials struct {
					TenantID Env[string] `yaml:"tenant_id,omitempty"`
					ClientID Env[string] `yaml:"client_id,omitempty"`
					Secret   Env[string] `yaml:"client_secret,omitempty"`
				} `yaml:"credentials,omitempty"`
				ManagedIdentity struct {
					ClientID Env[string] `yaml:"client_id,omitempty"`
				} `yaml:"managed_identity,omitempty"`
			} `yaml:"keyvault,omitempty"`
		} `yaml:"azure,omitempty"`

		Gemalto struct {
			KeySecure struct {
				Endpoint Env[string] `yaml:"endpoint,omitempty"`

				Login struct {
					Token  Env[string]        `yaml:"token,omitempty"`
					Domain Env[string]        `yaml:"domain,omitempty"`
					Retry  Env[time.Duration] `yaml:"retry,omitempty"`
				} `yaml:"credentials,omitempty"`

				TLS struct {
					CAPath Env[string] `yaml:"ca,omitempty"`
				} `yaml:"tls,omitempty"`
			} `yaml:"keysecure,omitempty"`
		} `yaml:"gemalto,omitempty"`
	} `yaml:"keystore,omitempty"`
}

func serverConfigToYAML(config *ServerConfig) *serverConfigYAML {
	yml := new(serverConfigYAML)
	yml.Addr = config.Addr
	yml.Admin.Identity = config.Admin

	// TLS
	yml.TLS.PrivateKey = config.TLS.PrivateKey
	yml.TLS.Certificate = config.TLS.Certificate
	yml.TLS.Password = config.TLS.Password
	yml.TLS.Proxy.Identities = config.TLS.Proxies
	yml.TLS.Proxy.Header.ClientCert = config.TLS.ForwardCertHeader

	// Cache
	yml.Cache.Expiry.Any = config.Cache.Expiry
	yml.Cache.Expiry.Unused = config.Cache.ExpiryUnused
	yml.Cache.Expiry.Offline = config.Cache.ExpiryOffline

	// Log
	yml.Log.Audit = config.Log.Audit
	yml.Log.Error = config.Log.Error

	// Policies
	yml.Policies = make(map[string]struct {
		Allow      []string            `yaml:"allow,omitempty"`
		Deny       []string            `yaml:"deny,omitempty"`
		Identities []Env[kes.Identity] `yaml:"identities,omitempty"`
	}, len(config.Policies))
	for name, policy := range config.Policies {
		type Item struct {
			Allow      []string            `yaml:"allow,omitempty"`
			Deny       []string            `yaml:"deny,omitempty"`
			Identities []Env[kes.Identity] `yaml:"identities,omitempty"`
		}
		yml.Policies[name] = Item{
			Allow:      policy.Allow,
			Deny:       policy.Deny,
			Identities: policy.Identities,
		}
	}

	// Keys
	for _, key := range config.Keys {
		type Item struct {
			Name Env[string] `yaml:"name,omitempty"`
		}
		yml.Keys = append(yml.Keys, Item{
			Name: key.Name,
		})
	}

	// KeyStore
	if config.KMS != nil {
		config.KMS.toYAML(yml)
	}
	return yml
}

func yamlToServerConfig(yml *serverConfigYAML) *ServerConfig {
	config := new(ServerConfig)
	config.Addr = yml.Addr
	config.Admin = yml.Admin.Identity

	// TLS
	config.TLS.PrivateKey = yml.TLS.PrivateKey
	config.TLS.Certificate = yml.TLS.Certificate
	config.TLS.Password = yml.TLS.Password
	config.TLS.Proxies = yml.TLS.Proxy.Identities
	config.TLS.ForwardCertHeader = yml.TLS.Proxy.Header.ClientCert

	// Cache
	config.Cache.Expiry = yml.Cache.Expiry.Any
	config.Cache.ExpiryUnused = yml.Cache.Expiry.Unused
	config.Cache.ExpiryOffline = yml.Cache.Expiry.Offline

	// Log
	config.Log.Audit = yml.Log.Audit
	config.Log.Error = yml.Log.Error

	// Policies
	config.Policies = make(map[string]Policy, len(yml.Policies))
	for name, policy := range yml.Policies {
		config.Policies[name] = Policy{
			Allow:      policy.Allow,
			Deny:       policy.Deny,
			Identities: policy.Identities,
		}
	}

	// Keys
	for _, key := range yml.Keys {
		config.Keys = append(config.Keys, Key{
			Name: key.Name,
		})
	}

	// Keystore
	switch {
	case yml.KeyStore.Fs.Path.Value != "":
		config.KMS = new(FSConfig)
	case yml.KeyStore.Generic.Endpoint.Value != "":
		config.KMS = new(KMSPluginConfig)
	case yml.KeyStore.Vault.Endpoint.Value != "":
		config.KMS = new(VaultConfig)
	case yml.KeyStore.Fortanix.SDKMS.Endpoint.Value != "":
		config.KMS = new(FortanixConfig)
	case yml.KeyStore.Aws.SecretsManager.Endpoint.Value != "":
		config.KMS = new(SecretsManagerConfig)
	case yml.KeyStore.GCP.SecretManager.ProjectID.Value != "":
		config.KMS = new(SecretsManagerConfig)
	case yml.KeyStore.Azure.KeyVault.Endpoint.Value != "":
		config.KMS = new(KeyVaultConfig)
	case yml.KeyStore.Gemalto.KeySecure.Endpoint.Value != "":
		config.KMS = new(KeySecureConfig)
	default:
		config.KMS = new(memConfig)
	}
	config.KMS.fromYAML(yml)
	return config
}
