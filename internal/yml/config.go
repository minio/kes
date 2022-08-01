// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package yml

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/minio/kes"
	"gopkg.in/yaml.v3"
)

// ReadServerConfig reads file named by filename and returns
// the deserialized ServerConfig.
func ReadServerConfig(filename string) (*ServerConfig, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	c, err := unmarshalServerConfig(b)
	if err != nil {
		return nil, err
	}

	// Set default values for empty fields
	if c.Cache.Expiry.Any.Value() == 0 {
		c.Cache.Expiry.Any.value = 5 * time.Minute
	}
	if c.Cache.Expiry.Unused.Value() == 0 {
		c.Cache.Expiry.Unused.value = 30 * time.Second
	}
	if c.Log.Audit.Value() == "" {
		c.Log.Audit.value = "off"
	}
	if c.Log.Error.Value() == "" {
		c.Log.Error.value = "on"
	}
	if c.KeyStore.Vault.Engine.Value() == "" {
		c.KeyStore.Vault.Engine.value = "kv"
	}
	if c.KeyStore.Vault.APIVersion.Value() == "" {
		c.KeyStore.Vault.APIVersion.value = "v1"
	}
	if c.KeyStore.Vault.AppRole.Engine.Value() == "" {
		c.KeyStore.Vault.AppRole.Engine.value = "approle"
	}
	if c.KeyStore.Vault.AppRole.Retry.Value() == 0 {
		c.KeyStore.Vault.AppRole.Retry.value = 5 * time.Second
	}
	if c.KeyStore.Vault.Kubernetes.Engine.Value() == "" {
		c.KeyStore.Vault.Kubernetes.Engine.value = "kubernetes"
	}
	if c.KeyStore.Vault.Kubernetes.Retry.Value() == 0 {
		c.KeyStore.Vault.AppRole.Retry.value = 5 * time.Second
	}
	if c.KeyStore.GCP.SecretManager.Endpoint.Value() == "" {
		c.KeyStore.GCP.SecretManager.Endpoint.value = "secretmanager.googleapis.com:443"
	}

	// We treat the Hashicorp Vault Kubernetes JWT specially since it
	// can either be the raw JWT or a path to file containing the JWT.
	//
	// Therefore, we check whether such a file exists, and if so, replace
	// the JWT value with its content.
	if c.KeyStore.Vault.Endpoint.Value() != "" && c.KeyStore.Vault.Kubernetes.JWT.Value() != "" {
		f, err := os.Open(c.KeyStore.Vault.Kubernetes.JWT.Value())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("yml: failed to open Vault Kubernetes JWT: %v", err)
		}
		if err == nil {
			jwt, err := ioutil.ReadAll(f)
			if err != nil {
				return nil, fmt.Errorf("yml: failed to read Vault Kubernetes JWT: %v", err)
			}
			c.KeyStore.Vault.Kubernetes.JWT.value = string(jwt)
		}
	}

	// Validate the ServerConfig and report obvious configuration
	// errors.
	for _, identity := range c.TLS.Proxy.Identities {
		if identity.Value().IsUnknown() {
			continue
		}
		if identity.Value() == c.Admin.Identity.Value() {
			return nil, errors.New("yml: TLS proxy contains admin identity: admin identity cannot be used as TLS proxy")
		}
	}

	if v := strings.ToLower(c.Log.Audit.Value()); v != "on" && v != "off" {
		return nil, errors.New("yml: invalid audit log configuration: allowed values are { on | off }")
	}
	if v := strings.ToLower(c.Log.Error.Value()); v != "on" && v != "off" {
		return nil, errors.New("yml: invalid error log configuration: allowed values are { on | off }")
	}

	identitySet := map[kes.Identity]string{}
	for name, policy := range c.Policies {
		for _, identity := range policy.Identities {
			if identity.Value().IsUnknown() {
				continue
			}
			if identity.Value() == c.Admin.Identity.Value() {
				return nil, fmt.Errorf("yml: policy %q contains admin identity", name)
			}
			for _, proxyIdentity := range c.TLS.Proxy.Identities {
				if identity.Value() == proxyIdentity.Value() {
					return nil, fmt.Errorf("yml: policy %q contains TLS proxy identity", name)
				}
			}
			if policyName, ok := identitySet[identity.Value()]; ok {
				return nil, fmt.Errorf("yml: identity %q assigned to multiple policies: %q and %q", identity.Value(), name, policyName)
			}
			identitySet[identity.Value()] = name
		}
	}

	var a backend
	for _, b := range c.backends() {
		if a.Endpoint != "" && b.Endpoint != "" {
			return nil, fmt.Errorf("yml: ambiguous KMS configuration: %s and %s KMS key store specified at the same time", a.Type, b.Type)
		}
		if b.Endpoint != "" {
			a = b
		}
	}

	if c.KeyStore.Vault.Endpoint.Value() != "" {
		if c.KeyStore.Vault.AppRole.ID.Value() != "" || c.KeyStore.Vault.AppRole.Secret.Value() != "" {
			if c.KeyStore.Vault.Kubernetes.Role.Value() != "" || c.KeyStore.Vault.Kubernetes.JWT.Value() != "" {
				return nil, errors.New("yml: amiguous KMS configuration: Hashicorp Vault AppRole and Kubernetes credentials found")
			}
		}
	}
	return c, nil
}

func unmarshalServerConfig(b []byte) (*ServerConfig, error) {
	var config ServerConfig
	if err := yaml.Unmarshal(b, &config); err != nil {
		if _, ok := err.(*yaml.TypeError); !ok {
			return nil, err
		}

		var configV0170 serverConfigV0170
		if errV0170 := yaml.Unmarshal(b, &configV0170); errV0170 != nil {
			if _, ok := errV0170.(*yaml.TypeError); !ok {
				return nil, err
			}
		}
		return configV0170.migrate(), nil
	}
	return &config, nil
}
