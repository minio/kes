// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

type serverConfigV0140 struct {
	Addr String   `yaml:"address"`
	Root Identity `yaml:"root"`

	TLS struct {
		PrivateKey  String `yaml:"key"`
		Certificate String `yaml:"cert"`
		Proxy       struct {
			Identities []Identity `yaml:"identities"`
			Header     struct {
				ClientCert String `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`
	} `yaml:"tls"`

	Policies map[string]struct {
		Paths      []string   `yaml:"paths"` // Use 'string' type; We don't replace API path patterns with env. vars
		Identities []Identity `yaml:"identities"`
	} `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any     Duration `yaml:"any"`
			Unused  Duration `yaml:"unused"`
			Offline Duration `yaml:"offline"`
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error String `yaml:"error"`
		Audit String `yaml:"audit"`
	} `yaml:"log"`

	Keys []struct {
		Name String `yaml:"name"`
	} `yaml:"keys"`

	KeyStore struct {
		Fs struct {
			Path String `yaml:"path"`
		} `yaml:"fs"`

		Generic struct {
			Endpoint String `yaml:"endpoint"`
			TLS      struct {
				PrivateKey  String `yaml:"key"`
				Certificate String `yaml:"cert"`
				CAPath      String `yaml:"ca"`
			} `yaml:"tls"`
		} `yaml:"generic"`

		Vault struct {
			Endpoint   String `yaml:"endpoint"`
			Engine     String `yaml:"engine"`
			APIVersion String `yaml:"version"`
			Namespace  String `yaml:"namespace"`

			Prefix String `yaml:"prefix"`

			AppRole struct {
				Engine String   `yaml:"engine"`
				ID     String   `yaml:"id"`
				Secret String   `yaml:"secret"`
				Retry  Duration `yaml:"retry"`
			} `yaml:"approle"`

			Kubernetes struct {
				Engine String   `yaml:"engine"`
				Role   String   `yaml:"role"`
				JWT    String   `yaml:"jwt"` // Can be either a JWT or a path to a file containing a JWT
				Retry  Duration `yaml:"retry"`
			} `yaml:"kubernetes"`

			TLS struct {
				PrivateKey  String `yaml:"key"`
				Certificate String `yaml:"cert"`
				CAPath      String `yaml:"ca"`
			} `yaml:"tls"`

			Status struct {
				Ping Duration `yaml:"ping"`
			} `yaml:"status"`
		} `yaml:"vault"`

		Fortanix struct {
			SDKMS struct {
				Endpoint String `yaml:"endpoint"`
				GroupID  String `yaml:"group_id"`

				Login struct {
					APIKey String `yaml:"key"`
				} `yaml:"credentials"`

				TLS struct {
					CAPath String `yaml:"ca"`
				} `yaml:"tls"`
			} `yaml:"sdkms"`
		} `yaml:"fortanix"`

		Aws struct {
			SecretsManager struct {
				Endpoint String `yaml:"endpoint"`
				Region   String `yaml:"region"`
				KmsKey   String ` yaml:"kmskey"`

				Login struct {
					AccessKey    String `yaml:"accesskey"`
					SecretKey    String `yaml:"secretkey"`
					SessionToken String `yaml:"token"`
				} `yaml:"credentials"`
			} `yaml:"secretsmanager"`
		} `yaml:"aws"`

		GCP struct {
			SecretManager struct {
				ProjectID   String `yaml:"project_id"`
				Endpoint    String `yaml:"endpoint"`
				Credentials struct {
					Client   String `yaml:"client_email"`
					ClientID String `yaml:"client_id"`
					KeyID    String `yaml:"private_key_id"`
					Key      String `yaml:"private_key"`
				} `yaml:"credentials"`
			} `yaml:"secretmanager"`
		} `yaml:"gcp"`

		Azure struct {
			KeyVault struct {
				Endpoint    String `yaml:"endpoint"`
				Credentials struct {
					TenantID String `yaml:"tenant_id"`
					ClientID String `yaml:"client_id"`
					Secret   String `yaml:"client_secret"`
				} `yaml:"credentials"`
				ManagedIdentity struct {
					ClientID String `yaml:"client_id"`
				} `yaml:"managed_identity"`
			} `yaml:"keyvault"`
		} `yaml:"azure"`

		Gemalto struct {
			KeySecure struct {
				Endpoint String `yaml:"endpoint"`

				Login struct {
					Token  String   `yaml:"token"`
					Domain String   `yaml:"domain"`
					Retry  Duration `yaml:"retry"`
				} `yaml:"credentials"`

				TLS struct {
					CAPath String `yaml:"ca"`
				} `yaml:"tls"`
			} `yaml:"keysecure"`
		} `yaml:"gemalto"`
	} `yaml:"keystore"`
}

func (c *serverConfigV0140) migrate() *ServerConfig {
	config := &ServerConfig{
		Address:  c.Addr,
		Cache:    c.Cache,
		Log:      c.Log,
		Keys:     c.Keys,
		KeyStore: c.KeyStore,
	}
	config.Admin.Identity = c.Root

	config.TLS.PrivateKey = c.TLS.PrivateKey
	config.TLS.Certificate = c.TLS.Certificate
	config.TLS.Proxy = c.TLS.Proxy

	type Policy struct {
		Allow      []string   `yaml:"allow"`
		Deny       []string   `yaml:"deny"`
		Identities []Identity `yaml:"identities"`
	}
	config.Policies = make(map[string]struct {
		Allow      []string   `yaml:"allow"`
		Deny       []string   `yaml:"deny"`
		Identities []Identity `yaml:"identities"`
	}, len(c.Policies))
	for name, policy := range c.Policies {
		config.Policies[name] = Policy{
			Allow:      policy.Paths,
			Identities: policy.Identities,
		}
	}
	return config
}
