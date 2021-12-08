// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

// ServerConfig is the structure containing all
// possible KES server configuration fields.
//
// It can be (de)serialized from/into YAML.
type ServerConfig struct {
	Address String `yaml:"address"`

	Admin struct {
		Identity Identity `yaml:"identity"`
	} `yaml:"admin"`

	TLS struct {
		PrivateKey  String `yaml:"key"`
		Certificate String `yaml:"cert"`
		Password    String `yaml:"password"`

		Proxy struct {
			Identities []Identity `yaml:"identities"`
			Header     struct {
				ClientCert String `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`
	} `yaml:"tls"`

	Policies map[string]struct {
		Allow      []string   `yaml:"allow"` // Use 'string' type; We don't replace API allow patterns with env. vars
		Deny       []string   `yaml:"deny"`  // Use 'string' type; We don't replace API deny patterns with env. vars
		Identities []Identity `yaml:"identity"`
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

type backend struct {
	Type     string
	Endpoint string
}

func (c *ServerConfig) backends() []backend {
	return []backend{
		backend{Type: "FS", Endpoint: c.KeyStore.Fs.Path.Value()},
		backend{Type: "Generic", Endpoint: c.KeyStore.Generic.Endpoint.Value()},
		backend{Type: "Hashicorp Vault", Endpoint: c.KeyStore.Vault.Endpoint.Value()},
		backend{Type: "Fortanix SDKMS", Endpoint: c.KeyStore.Fortanix.SDKMS.Endpoint.Value()},
		backend{Type: "Gemalto KeySecure", Endpoint: c.KeyStore.Gemalto.KeySecure.Endpoint.Value()},
		backend{Type: "AWS SecretsManager", Endpoint: c.KeyStore.Aws.SecretsManager.Endpoint.Value()},
		backend{Type: "GCP SecretManager", Endpoint: c.KeyStore.GCP.SecretManager.ProjectID.Value()},
		backend{Type: "Azure KeyVault", Endpoint: c.KeyStore.Azure.KeyVault.Endpoint.Value()},
	}
}
