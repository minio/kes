// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package edge

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/minio/kes-go"
	"gopkg.in/yaml.v3"
)

type yml struct {
	Version string `yaml:"version"`

	Addr env[string] `yaml:"address"`

	Admin struct {
		Identity env[kes.Identity] `yaml:"identity"`
	} `yaml:"admin"`

	TLS struct {
		PrivateKey  env[string] `yaml:"key"`
		Certificate env[string] `yaml:"cert"`
		CAPath      env[string] `yaml:"ca"`
		Password    env[string] `yaml:"password"`

		Proxy struct {
			Identities []env[kes.Identity] `yaml:"identities"`
			Header     struct {
				ClientCert env[string] `yaml:"cert"`
			} `yaml:"header"`
		} `yaml:"proxy"`
	} `yaml:"tls"`

	Policies map[string]struct {
		Allow      []string            `yaml:"allow"`
		Deny       []string            `yaml:"deny"`
		Identities []env[kes.Identity] `yaml:"identities"`
	} `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any     env[time.Duration] `yaml:"any"`
			Unused  env[time.Duration] `yaml:"unused"`
			Offline env[time.Duration] `yaml:"offline"`
		} `yaml:"expiry"`
	} `yaml:"cache"`

	API struct {
		Paths map[string]struct {
			InsecureSkipAuth env[bool]          `yaml:"skip_auth"`
			Timeout          env[time.Duration] `yaml:"timeout"`
		} `yaml:",inline"`
	} `yaml:"api"`

	Log struct {
		Error env[string] `yaml:"error"`
		Audit env[string] `yaml:"audit"`
	} `yaml:"log"`

	Keys []struct {
		Name env[string] `yaml:"name"`
	} `yaml:"keys"`

	KeyStore struct {
		FS *struct {
			Path env[string] `yaml:"path"`
		}
		KES *struct {
			Endpoint []env[string] `yaml:"endpoint"`
			Enclave  env[string]   `yaml:"enclave"`
			TLS      struct {
				Certificate env[string] `yaml:"cert"`
				PrivateKey  env[string] `yaml:"key"`
				CAPath      env[string] `yaml:"ca"`
			} `yaml:"tls"`
		} `yaml:"kes"`

		Vault *struct {
			Endpoint   env[string] `yaml:"endpoint"`
			Engine     env[string] `yaml:"engine"`
			APIVersion env[string] `yaml:"version"`
			Namespace  env[string] `yaml:"namespace"`
			Prefix     env[string] `yaml:"prefix"`

			AppRole *struct {
				Engine env[string] `yaml:"engine"`
				ID     env[string] `yaml:"id"`
				Secret env[string] `yaml:"secret"`
			} `yaml:"approle"`

			Kubernetes *struct {
				Engine env[string] `yaml:"engine"`
				Role   env[string] `yaml:"role"`
				JWT    env[string] `yaml:"jwt"` // Can be either a JWT or a path to a file containing a JWT
			} `yaml:"kubernetes"`

			TLS struct {
				PrivateKey  env[string] `yaml:"key"`
				Certificate env[string] `yaml:"cert"`
				CAPath      env[string] `yaml:"ca"`
			} `yaml:"tls"`

			Status struct {
				Ping env[time.Duration] `yaml:"ping"`
			} `yaml:"status"`
		} `yaml:"vault"`

		Fortanix *struct {
			SDKMS *struct {
				Endpoint env[string] `yaml:"endpoint"`
				GroupID  env[string] `yaml:"group_id"`

				Login struct {
					APIKey env[string] `yaml:"key"`
				} `yaml:"credentials"`

				TLS struct {
					CAPath env[string] `yaml:"ca"`
				} `yaml:"tls"`
			} `yaml:"sdkms"`
		} `yaml:"fortanix"`

		Gemalto *struct {
			KeySecure *struct {
				Endpoint env[string] `yaml:"endpoint"`

				Login struct {
					Token  env[string] `yaml:"token"`
					Domain env[string] `yaml:"domain"`
				} `yaml:"credentials"`

				TLS struct {
					CAPath env[string] `yaml:"ca"`
				} `yaml:"tls"`
			} `yaml:"keysecure"`
		} `yaml:"gemalto"`

		GCP *struct {
			SecretManager *struct {
				ProjectID   env[string]   `yaml:"project_id"`
				Endpoint    env[string]   `yaml:"endpoint"`
				Scopes      []env[string] `yaml:"scopes"`
				Credentials struct {
					Client   env[string] `yaml:"client_email"`
					ClientID env[string] `yaml:"client_id"`
					KeyID    env[string] `yaml:"private_key_id"`
					Key      env[string] `yaml:"private_key"`
				} `yaml:"credentials"`
			} `yaml:"secretmanager"`
		} `yaml:"gcp"`

		AWS *struct {
			SecretsManager *struct {
				Endpoint env[string] `yaml:"endpoint"`
				Region   env[string] `yaml:"region"`
				KmsKey   env[string] ` yaml:"kmskey"`

				Login struct {
					AccessKey    env[string] `yaml:"accesskey"`
					SecretKey    env[string] `yaml:"secretkey"`
					SessionToken env[string] `yaml:"token"`
				} `yaml:"credentials"`
			} `yaml:"secretsmanager"`
		} `yaml:"aws"`

		Azure *struct {
			KeyVault *struct {
				Endpoint    env[string] `yaml:"endpoint"`
				Credentials *struct {
					TenantID env[string] `yaml:"tenant_id"`
					ClientID env[string] `yaml:"client_id"`
					Secret   env[string] `yaml:"client_secret"`
				} `yaml:"credentials"`
				ManagedIdentity *struct {
					ClientID env[string] `yaml:"client_id"`
				} `yaml:"managed_identity"`
			} `yaml:"keyvault"`
		} `yaml:"azure"`

		OpenStack *struct {
			Barbican *struct {
				AuthUrl env[string] `yaml:"auth_url"`

				Credentials *struct {
					UserDomain    env[string] `yaml:"user_domain"`
					Username      env[string] `yaml:"username"`
					Password      env[string] `yaml:"password"`
					ProjectDomain env[string] `yaml:"project_domain"`
					ProjectName   env[string] `yaml:"project_name"`
					ServiceType   env[string] `yaml:"service_type"`
					ServiceName   env[string] `yaml:"service_name"`
					Region        env[string] `yaml:"region"`
				} `yaml:"credentials"`
			} `yaml:"barbican"`
		} `yaml:"openstack"`
	} `yaml:"keystore"`
}

func findVersion(root *yaml.Node) (string, error) {
	if root == nil {
		return "", errors.New("edge: invalid server config")
	}
	if root.Kind != yaml.DocumentNode {
		return "", errors.New("edge: invalid server config")
	}
	if len(root.Content) != 1 {
		return "", errors.New("edge: invalid server config")
	}

	doc := root.Content[0]
	for i, n := range doc.Content {
		if n.Value == "version" {
			if n.Kind != yaml.ScalarNode {
				return "", fmt.Errorf("edge: invalid server config version at line '%d'", n.Line)
			}
			if i == len(doc.Content)-1 {
				return "", fmt.Errorf("edge: invalid server config version at line '%d'", n.Line)
			}
			v := doc.Content[i+1]
			if v.Kind != yaml.ScalarNode {
				return "", fmt.Errorf("edge: invalid server config version at line '%d'", v.Line)
			}
			return v.Value, nil
		}
	}
	return "", nil
}

func ymlToServerConfig(y *yml) (*ServerConfig, error) {
	if y.Version != "" && y.Version != "v1" {
		return nil, fmt.Errorf("edge: invalid version '%s'", y.Version)
	}
	if y.Admin.Identity.Value.IsUnknown() {
		return nil, errors.New("edge: invalid admin identity: no admin identity")
	}
	if y.TLS.PrivateKey.Value == "" {
		return nil, errors.New("edge: invalid tls config: no private key")
	}
	if y.TLS.Certificate.Value == "" {
		return nil, errors.New("edge: invalid tls config: no certificate")
	}

	for _, proxy := range y.TLS.Proxy.Identities {
		if proxy.Value == y.Admin.Identity.Value {
			return nil, fmt.Errorf("edge: invalid tls proxy: identity '%s' is already admin", proxy.Value)
		}
	}

	for name, policy := range y.Policies {
		for _, identity := range policy.Identities {
			if identity.Value == y.Admin.Identity.Value {
				return nil, fmt.Errorf("edge: invalid policy '%s': identity '%s' is already admin", name, identity.Value)
			}
			for _, proxy := range y.TLS.Proxy.Identities {
				if identity.Value == proxy.Value {
					return nil, fmt.Errorf("edge: invalid policy '%s': identity '%s' is already a TLS proxy", name, identity.Value)
				}
			}
		}
	}

	if y.Cache.Expiry.Any.Value < 0 {
		return nil, fmt.Errorf("edge: invalid cache expiry '%v'", y.Cache.Expiry.Any.Value)
	}
	if y.Cache.Expiry.Unused.Value < 0 {
		return nil, fmt.Errorf("edge: invalid cache unused expiry '%v'", y.Cache.Expiry.Unused.Value)
	}
	if y.Cache.Expiry.Offline.Value < 0 {
		return nil, fmt.Errorf("edge: invalid offline cache expiry '%v'", y.Cache.Expiry.Offline.Value)
	}

	if v := strings.ToLower(strings.TrimSpace(y.Log.Error.Value)); v != "on" && v != "off" && v != "" {
		return nil, fmt.Errorf("edge: invalid error log config '%v'", y.Log.Error.Value)
	}
	if v := strings.ToLower(strings.TrimSpace(y.Log.Audit.Value)); v != "on" && v != "off" && v != "" {
		return nil, fmt.Errorf("edge: invalid audit log config '%v'", y.Log.Audit.Value)
	}

	for path, api := range y.API.Paths {
		if api.Timeout.Value < 0 {
			return nil, fmt.Errorf("edge: invalid timeout '%d' for API '%s'", api.Timeout.Value, path)
		}
	}

	if len(y.Keys) > 0 {
		names := make(map[string]struct{}, len(y.Keys))
		for _, key := range y.Keys {
			if _, ok := names[key.Name.Value]; ok {
				return nil, fmt.Errorf("edge: invalid key config: key '%s' is defined multiple times", key.Name.Value)
			}
			names[key.Name.Value] = struct{}{}
		}
	}

	keystore, err := ymlToKeyStore(y)
	if err != nil {
		return nil, err
	}

	c := &ServerConfig{
		Addr:  y.Addr.Value,
		Admin: y.Admin.Identity.Value,
		TLS: &TLSConfig{
			PrivateKey:        y.TLS.PrivateKey.Value,
			Certificate:       y.TLS.Certificate.Value,
			Password:          y.TLS.Password.Value,
			CAPath:            y.TLS.CAPath.Value,
			ForwardCertHeader: y.TLS.Proxy.Header.ClientCert.Value,
		},
		Cache: &CacheConfig{
			Expiry:        y.Cache.Expiry.Any.Value,
			ExpiryUnused:  y.Cache.Expiry.Unused.Value,
			ExpiryOffline: y.Cache.Expiry.Offline.Value,
		},
		Log: &LogConfig{
			Error: strings.TrimSpace(strings.ToLower(y.Log.Error.Value)) != "off", // default is "on" behavior
			Audit: strings.TrimSpace(strings.ToLower(y.Log.Audit.Value)) == "on",  // default is "off" behavior
		},
		KeyStore: keystore,
	}
	if len(y.TLS.Proxy.Identities) > 0 {
		c.TLS.Proxies = make([]kes.Identity, 0, len(y.TLS.Proxy.Identities))
		for _, proxy := range y.TLS.Proxy.Identities {
			c.TLS.Proxies = append(c.TLS.Proxies, proxy.Value)
		}
	}
	if len(y.Policies) > 0 {
		c.Policies = make(map[string]Policy, len(y.Policies))
		for name, policy := range y.Policies {
			identities := make([]kes.Identity, 0, len(policy.Identities))
			for _, id := range policy.Identities {
				identities = append(identities, id.Value)
			}
			c.Policies[name] = Policy{
				Allow:      policy.Allow,
				Deny:       policy.Deny,
				Identities: identities,
			}
		}
	}
	if len(y.API.Paths) > 0 {
		paths := make(map[string]APIPathConfig, len(y.API.Paths))
		for path, api := range y.API.Paths {
			paths[path] = APIPathConfig{
				InsecureSkipAuth: api.InsecureSkipAuth.Value,
				Timeout:          api.Timeout.Value,
			}
		}
		c.API = &APIConfig{
			Paths: paths,
		}
	}
	for path, api := range y.API.Paths {
		if api.Timeout.Value < 0 {
			return nil, fmt.Errorf("edge: invalid timeout '%d' for API '%s'", api.Timeout.Value, path)
		}
	}
	if len(y.Keys) > 0 {
		c.Keys = make([]Key, 0, len(y.Keys))
		for _, key := range y.Keys {
			c.Keys = append(c.Keys, Key{Name: key.Name.Value})
		}
	}
	return c, nil
}

func ymlToKeyStore(y *yml) (KeyStore, error) {
	var keystore KeyStore

	// FS Keystore
	if y.KeyStore.FS != nil {
		if y.KeyStore.FS.Path.Value == "" {
			return nil, errors.New("edge: invalid fs keystore: no path specified")
		}
		keystore = &FSKeyStore{
			Path: y.KeyStore.FS.Path.Value,
		}
	}

	// KES Keystore
	if y.KeyStore.KES != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		endpoints := make([]string, 0, len(y.KeyStore.KES.Endpoint))
		for _, endpoint := range y.KeyStore.KES.Endpoint {
			if e := strings.TrimSpace(endpoint.Value); e != "" {
				endpoints = append(endpoints, e)
			}
		}
		if len(endpoints) == 0 {
			return nil, errors.New("edge: invalid kes keystore: no endpoint specified")
		}
		if y.KeyStore.KES.TLS.PrivateKey.Value == "" {
			return nil, errors.New("edge: invalid kes keystore: no TLS private key specified")
		}
		if y.KeyStore.KES.TLS.Certificate.Value == "" {
			return nil, errors.New("edge: invalid kes keystore: no TLS certificate specified")
		}
		keystore = &KESKeyStore{
			Endpoints:       endpoints,
			Enclave:         y.KeyStore.KES.Enclave.Value,
			PrivateKeyFile:  y.KeyStore.KES.TLS.PrivateKey.Value,
			CertificateFile: y.KeyStore.KES.TLS.Certificate.Value,
			CAPath:          y.KeyStore.KES.TLS.CAPath.Value,
		}
	}

	// Hashicorp Vault Keystore
	if y.KeyStore.Vault != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.Vault.Endpoint.Value == "" {
			return nil, errors.New("edge: invalid vault keystore: no endpoint specified")
		}
		if y.KeyStore.Vault.AppRole == nil && y.KeyStore.Vault.Kubernetes == nil {
			return nil, errors.New("edge: invalid vault keystore: no authentication method specified")
		}
		if y.KeyStore.Vault.AppRole != nil && y.KeyStore.Vault.Kubernetes != nil {
			return nil, errors.New("edge: invalid vault keystore: more than one authentication method specified")
		}
		if y.KeyStore.Vault.AppRole != nil {
			if y.KeyStore.Vault.AppRole.ID.Value == "" {
				return nil, errors.New("edge: invalid vault keystore: invalid approle config: no approle ID specified")
			}
			if y.KeyStore.Vault.AppRole.Secret.Value == "" {
				return nil, errors.New("edge: invalid vault keystore: invalid approle config: no approle secret specified")
			}
		}
		if y.KeyStore.Vault.Kubernetes != nil {
			if y.KeyStore.Vault.Kubernetes.JWT.Value == "" {
				return nil, errors.New("edge: invalid vault keystore: invalid kubernetes config: no JWT specified")
			}

			// If the passed JWT value contains a path separator we assume it's a file.
			// We always check for '/' and the OS-specific one make cover cases where
			// a path is specified using '/' but the underlying OS is e.g. windows.
			if jwt := y.KeyStore.Vault.Kubernetes.JWT.Value; strings.ContainsRune(jwt, '/') || strings.ContainsRune(jwt, os.PathSeparator) {
				b, err := os.ReadFile(y.KeyStore.Vault.Kubernetes.JWT.Value)
				if err != nil {
					return nil, fmt.Errorf("edge: failed to read vault kubernetes JWT from '%s': %v", y.KeyStore.Vault.Kubernetes.JWT.Value, err)
				}
				y.KeyStore.Vault.Kubernetes.JWT.Value = string(b)
			}
		}
		if y.KeyStore.Vault.TLS.PrivateKey.Value != "" && y.KeyStore.Vault.TLS.Certificate.Value == "" {
			return nil, errors.New("edge: invalid vault keystore: invalid tls config: no TLS certificate provided")
		}
		if y.KeyStore.Vault.TLS.PrivateKey.Value == "" && y.KeyStore.Vault.TLS.Certificate.Value != "" {
			return nil, errors.New("edge: invalid vault keystore: invalid tls config: no TLS private key provided")
		}
		s := &VaultKeyStore{
			Endpoint:    y.KeyStore.Vault.Endpoint.Value,
			Namespace:   y.KeyStore.Vault.Namespace.Value,
			APIVersion:  y.KeyStore.Vault.APIVersion.Value,
			Engine:      y.KeyStore.Vault.Engine.Value,
			Prefix:      y.KeyStore.Vault.Prefix.Value,
			PrivateKey:  y.KeyStore.Vault.TLS.PrivateKey.Value,
			Certificate: y.KeyStore.Vault.TLS.Certificate.Value,
			CAPath:      y.KeyStore.Vault.TLS.CAPath.Value,
			StatusPing:  y.KeyStore.Vault.Status.Ping.Value,
		}
		if y.KeyStore.Vault.AppRole != nil {
			s.AppRole = &VaultAppRoleAuth{
				Engine: y.KeyStore.Vault.AppRole.Engine.Value,
				ID:     y.KeyStore.Vault.AppRole.ID.Value,
				Secret: y.KeyStore.Vault.AppRole.Secret.Value,
			}
		}
		if y.KeyStore.Vault.Kubernetes != nil {
			s.Kubernetes = &VaultKubernetesAuth{
				Engine: y.KeyStore.Vault.Kubernetes.Engine.Value,
				JWT:    y.KeyStore.Vault.Kubernetes.JWT.Value,
				Role:   y.KeyStore.Vault.Kubernetes.Role.Value,
			}
		}
		keystore = s
	}

	// Fortanix SDKMS
	if y.KeyStore.Fortanix != nil && y.KeyStore.Fortanix.SDKMS != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.Fortanix.SDKMS.Endpoint.Value == "" {
			return nil, errors.New("edge: invalid fortanix SDKMS keystore: no endpoint specified")
		}
		if y.KeyStore.Fortanix.SDKMS.Login.APIKey.Value == "" {
			return nil, errors.New("edge: invalid fortanix SDKMS keystore: no API key specified")
		}
		keystore = &FortanixKeyStore{
			Endpoint: y.KeyStore.Fortanix.SDKMS.Endpoint.Value,
			GroupID:  y.KeyStore.Fortanix.SDKMS.GroupID.Value,
			APIKey:   y.KeyStore.Fortanix.SDKMS.Login.APIKey.Value,
			CAPath:   y.KeyStore.Fortanix.SDKMS.TLS.CAPath.Value,
		}
	}

	// Thales CipherTrust / Gemalto KeySecure
	if y.KeyStore.Gemalto != nil && y.KeyStore.Gemalto.KeySecure != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.Gemalto.KeySecure.Endpoint.Value == "" {
			return nil, errors.New("edge: invalid gemalto keysecure keystore: no endpoint specified")
		}
		if y.KeyStore.Gemalto.KeySecure.Login.Token.Value == "" {
			return nil, errors.New("edge: invalid gemalto keysecure keystore: no token specified")
		}
		keystore = &KeySecureKeyStore{
			Endpoint: y.KeyStore.Gemalto.KeySecure.Endpoint.Value,
			Token:    y.KeyStore.Gemalto.KeySecure.Login.Token.Value,
			Domain:   y.KeyStore.Gemalto.KeySecure.Login.Domain.Value,
			CAPath:   y.KeyStore.Gemalto.KeySecure.TLS.CAPath.Value,
		}
	}

	// GCP SecretManager
	if y.KeyStore.GCP != nil && y.KeyStore.GCP.SecretManager != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.GCP.SecretManager.ProjectID.Value == "" {
			return nil, errors.New("edge: invalid GCP secretmanager keystore: no project ID specified")
		}
		var scopes []string
		if len(y.KeyStore.GCP.SecretManager.Scopes) > 0 {
			scopes = make([]string, 0, len(scopes))
			for _, scope := range y.KeyStore.GCP.SecretManager.Scopes {
				scopes = append(scopes, scope.Value)
			}
		}
		keystore = &GCPSecretManagerKeyStore{
			ProjectID:   y.KeyStore.GCP.SecretManager.ProjectID.Value,
			Endpoint:    y.KeyStore.GCP.SecretManager.Endpoint.Value,
			ClientEmail: y.KeyStore.GCP.SecretManager.Credentials.Client.Value,
			ClientID:    y.KeyStore.GCP.SecretManager.Credentials.ClientID.Value,
			KeyID:       y.KeyStore.GCP.SecretManager.Credentials.KeyID.Value,
			Key:         y.KeyStore.GCP.SecretManager.Credentials.Key.Value,
			Scopes:      scopes,
		}
	}

	// AWS SecretsManager
	if y.KeyStore.AWS != nil && y.KeyStore.AWS.SecretsManager != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.AWS.SecretsManager.Endpoint.Value == "" {
			return nil, errors.New("edge: invalid AWS secretsmanager keystore: no endpoint specified")
		}
		if y.KeyStore.AWS.SecretsManager.Region.Value == "" {
			return nil, errors.New("edge: invalid AWS secretsmanager keystore: no region specified")
		}
		keystore = &AWSSecretsManagerKeyStore{
			Endpoint:     y.KeyStore.AWS.SecretsManager.Endpoint.Value,
			Region:       y.KeyStore.AWS.SecretsManager.Region.Value,
			KMSKey:       y.KeyStore.AWS.SecretsManager.KmsKey.Value,
			AccessKey:    y.KeyStore.AWS.SecretsManager.Login.AccessKey.Value,
			SecretKey:    y.KeyStore.AWS.SecretsManager.Login.SecretKey.Value,
			SessionToken: y.KeyStore.AWS.SecretsManager.Login.SessionToken.Value,
		}
	}

	// Azure KeyVault
	if y.KeyStore.Azure != nil && y.KeyStore.Azure.KeyVault != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.Azure.KeyVault.Endpoint.Value == "" {
			return nil, errors.New("edge: invalid Azure keyvault keystore: no endpoint specified")
		}
		if y.KeyStore.Azure.KeyVault.Credentials == nil && y.KeyStore.Azure.KeyVault.ManagedIdentity == nil {
			return nil, errors.New("edge: invalid Azure keyvault keystore: no authentication method specified")
		}
		if y.KeyStore.Azure.KeyVault.Credentials != nil && y.KeyStore.Azure.KeyVault.ManagedIdentity != nil {
			return nil, errors.New("edge: invalid Azure keyvault keystore: more than one authentication method specified")
		}
		if y.KeyStore.Azure.KeyVault.Credentials != nil {
			if y.KeyStore.Azure.KeyVault.Credentials.TenantID.Value == "" {
				return nil, errors.New("edge: invalid Azure keyvault keystore: no tenant ID specified")
			}
			if y.KeyStore.Azure.KeyVault.Credentials.ClientID.Value == "" {
				return nil, errors.New("edge: invalid Azure keyvault keystore: no client ID specified")
			}
			if y.KeyStore.Azure.KeyVault.Credentials.Secret.Value == "" {
				return nil, errors.New("edge: invalid Azure keyvault keystore: no client secret specified")
			}
		}
		if y.KeyStore.Azure.KeyVault.ManagedIdentity != nil {
			if y.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value == "" {
				return nil, errors.New("edge: invalid Azure keyvault keystore: no client ID specified")
			}
		}
		s := &AzureKeyVaultKeyStore{
			Endpoint: y.KeyStore.Azure.KeyVault.Endpoint.Value,
		}
		if y.KeyStore.Azure.KeyVault.Credentials != nil {
			s.TenantID = y.KeyStore.Azure.KeyVault.Credentials.TenantID.Value
			s.ClientID = y.KeyStore.Azure.KeyVault.Credentials.ClientID.Value
			s.ClientSecret = y.KeyStore.Azure.KeyVault.Credentials.Secret.Value
		}
		if y.KeyStore.Azure.KeyVault.ManagedIdentity != nil {
			s.ManagedIdentityClientID = y.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value
		}
		keystore = s
	}

	// OpenStack Barbican
	if y.KeyStore.OpenStack != nil && y.KeyStore.OpenStack.Barbican != nil {
		if keystore != nil {
			return nil, errors.New("edge: invalid keystore config: more than once keystore specified")
		}
		if y.KeyStore.OpenStack.Barbican.AuthUrl.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no Auth Url specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.UserDomain.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no User Domain specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.Username.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no Username specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.Password.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no Password specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.ProjectName.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no ProjectName specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.ServiceType.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no ServiceType specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.ServiceName.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no ServiceName specified")
		}
		if y.KeyStore.OpenStack.Barbican.Credentials.Region.Value == "" {
			return nil, errors.New("edge: invalid OpenStack Barbican keystore: no Region specified")
		}

		s := &OpenStackBarbicanKeyStore{
			AuthUrl:     y.KeyStore.OpenStack.Barbican.AuthUrl.Value,
			UserDomain:  y.KeyStore.OpenStack.Barbican.Credentials.UserDomain.Value,
			Username:    y.KeyStore.OpenStack.Barbican.Credentials.Username.Value,
			Password:    y.KeyStore.OpenStack.Barbican.Credentials.Password.Value,
			ProjectName: y.KeyStore.OpenStack.Barbican.Credentials.ProjectName.Value,
			ServiceType: y.KeyStore.OpenStack.Barbican.Credentials.ServiceType.Value,
			ServiceName: y.KeyStore.OpenStack.Barbican.Credentials.ServiceName.Value,
			Region:      y.KeyStore.OpenStack.Barbican.Credentials.Region.Value,
		}
		keystore = s
	}

	if keystore == nil {
		return nil, errors.New("edge: no keystore specified")
	}
	return keystore, nil
}

type env[T any] struct {
	Var   string
	Value T
}

func (r env[T]) MarshalYAML() (any, error) {
	if env := strings.TrimSpace(r.Var); env != "" {
		switch p, s := strings.HasPrefix(env, "${"), strings.HasSuffix(env, "}"); {
		case p && s:
			return env, nil
		case !p && !s:
			return "${" + env + "}", nil
		default:
			return nil, fmt.Errorf("edge: invalid env. variable reference '%s'", r.Var)
		}
	}
	return r.Value, nil
}

func (r *env[T]) UnmarshalYAML(node *yaml.Node) error {
	var env string
	if v := strings.TrimSpace(node.Value); strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
		env = strings.TrimSpace(v[2 : len(v)-1])
		v, ok := os.LookupEnv(env)
		if !ok {
			return fmt.Errorf("edge: line '%d' in YAML document: referenced env. variable '%s' not found", node.Line, env)
		}
		node.Value = v
	}

	var v T
	if err := node.Decode(&v); err != nil {
		return err
	}
	r.Var = env
	r.Value = v
	return nil
}
