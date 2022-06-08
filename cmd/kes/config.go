// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
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
)

// connect tries to establish a connection to the KMS specified in the ServerConfig
func connect(config *yml.ServerConfig, quiet quiet, errorLog *log.Logger) (key.Store, error) {
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
			if err = os.MkdirAll(config.KeyStore.Fs.Path.Value(), 0o700); err != nil {
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

		scopes := make([]string, 0, len(config.KeyStore.GCP.SecretManager.Scopes))
		for _, scope := range config.KeyStore.GCP.SecretManager.Scopes {
			if scope.Value() != "" {
				scopes = append(scopes, scope.Value())
			}
		}
		gcpStore, err := gcp.Connect(context.Background(), &gcp.Config{
			Endpoint:  config.KeyStore.GCP.SecretManager.Endpoint.Value(),
			ProjectID: config.KeyStore.GCP.SecretManager.ProjectID.Value(),
			Scopes:    scopes,
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
			err := azureStore.AuthenticateWithCredentials(azure.Credentials{
				TenantID: config.KeyStore.Azure.KeyVault.Credentials.TenantID.Value(),
				ClientID: config.KeyStore.Azure.KeyVault.Credentials.ClientID.Value(),
				Secret:   config.KeyStore.Azure.KeyVault.Credentials.Secret.Value(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
			}
		case config.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value() != "":
			err := azureStore.AuthenticateWithIdentity(azure.ManagedIdentity{
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

// policySetFromConfig returns an in-memory PolicySet
// from the given ServerConfig.
func policySetFromConfig(config *yml.ServerConfig) (auth.PolicySet, error) {
	policies := &policySet{
		policies: make(map[string]*auth.Policy),
	}
	for name, policy := range config.Policies {
		if _, ok := policies.policies[name]; ok {
			return nil, fmt.Errorf("policy %q already exists", name)
		}

		policies.policies[name] = &auth.Policy{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: time.Now().UTC(),
			CreatedBy: config.Admin.Identity.Value(),
		}
	}
	return policies, nil
}

type policySet struct {
	lock     sync.RWMutex
	policies map[string]*auth.Policy
}

var _ auth.PolicySet = (*policySet)(nil) // compiler check

func (p *policySet) Set(_ context.Context, name string, policy *auth.Policy) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.policies[name] = policy
	return nil
}

func (p *policySet) Get(_ context.Context, name string) (*auth.Policy, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	policy, ok := p.policies[name]
	if !ok {
		return nil, kes.ErrPolicyNotFound
	}
	return policy, nil
}

func (p *policySet) Delete(_ context.Context, name string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.policies, name)
	return nil
}

func (p *policySet) List(_ context.Context) (auth.PolicyIterator, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	names := make([]string, 0, len(p.policies))
	for name := range p.policies {
		names = append(names, name)
	}
	return &policyIterator{
		values: names,
	}, nil
}

type policyIterator struct {
	values  []string
	current string
}

var _ auth.PolicyIterator = (*policyIterator)(nil) // compiler check

func (i *policyIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *policyIterator) Name() string { return i.current }

func (i *policyIterator) Close() error { return nil }

// identitySetFromConfig returns an in-memory IdentitySet
// from the given ServerConfig.
func identitySetFromConfig(config *yml.ServerConfig) (auth.IdentitySet, error) {
	identities := &identitySet{
		admin:     config.Admin.Identity.Value(),
		createdAt: time.Now().UTC(),
		roles:     map[kes.Identity]auth.IdentityInfo{},
	}

	for name, policy := range config.Policies {
		for _, id := range policy.Identities {
			if id.Value().IsUnknown() {
				continue
			}

			if id.Value() == config.Admin.Identity.Value() {
				return nil, fmt.Errorf("identity %q is already an admin identity", id.Value())
			}
			if _, ok := identities.roles[id.Value()]; ok {
				return nil, fmt.Errorf("identity %q is already assigned", id.Value())
			}
			for _, proxyID := range config.TLS.Proxy.Identities {
				if id.Value() == proxyID.Value() {
					return nil, fmt.Errorf("identity %q is already a TLS proxy identity", id.Value())
				}
			}
			identities.roles[id.Value()] = auth.IdentityInfo{
				Policy:    name,
				CreatedAt: time.Now().UTC(),
				CreatedBy: config.Admin.Identity.Value(),
			}
		}
	}
	return identities, nil
}

type identitySet struct {
	admin     kes.Identity
	createdAt time.Time

	lock  sync.RWMutex
	roles map[kes.Identity]auth.IdentityInfo
}

var _ auth.IdentitySet = (*identitySet)(nil) // compiler check

func (i *identitySet) Admin(ctx context.Context) (kes.Identity, error) { return i.admin, nil }

func (i *identitySet) SetAdmin(context.Context, kes.Identity) error {
	return kes.NewError(http.StatusNotImplemented, "cannot set admin identity")
}

func (i *identitySet) Assign(_ context.Context, policy string, identity kes.Identity) error {
	if i.admin == identity {
		return kes.NewError(http.StatusBadRequest, "identity is root")
	}
	i.lock.Lock()
	defer i.lock.Unlock()

	i.roles[identity] = auth.IdentityInfo{
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
		CreatedBy: i.admin,
	}
	return nil
}

func (i *identitySet) Get(_ context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if identity == i.admin {
		return auth.IdentityInfo{
			IsAdmin:   true,
			CreatedAt: i.createdAt,
		}, nil
	}
	i.lock.RLock()
	defer i.lock.RUnlock()

	policy, ok := i.roles[identity]
	if !ok {
		return auth.IdentityInfo{}, auth.ErrIdentityNotFound
	}
	return policy, nil
}

func (i *identitySet) Delete(_ context.Context, identity kes.Identity) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	delete(i.roles, identity)
	return nil
}

func (i *identitySet) List(_ context.Context) (auth.IdentityIterator, error) {
	i.lock.RLock()
	defer i.lock.RUnlock()

	values := make([]kes.Identity, 0, len(i.roles))
	for identity := range i.roles {
		values = append(values, identity)
	}
	return &identityIterator{
		values: values,
	}, nil
}

type identityIterator struct {
	values  []kes.Identity
	current kes.Identity
}

var _ auth.IdentityIterator = (*identityIterator)(nil) // compiler check

func (i *identityIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *identityIterator) Identity() kes.Identity { return i.current }

func (i *identityIterator) Close() error { return nil }
