// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf

import (
	"testing"
	"time"
)

func TestReadServerConfigYAML_FS(t *testing.T) {
	const (
		Filename = "./testdata/fs.yml"
		FSPath   = "/tmp/keys"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	fs, ok := config.KeyStore.(*FSKeyStore)
	if !ok {
		var want *FSKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if fs.Path != FSPath {
		t.Fatalf("Invalid keystore: got path '%s' - want path '%s'", fs.Path, FSPath)
	}
}

func TestReadServerConfigYAML_EncryptedFS(t *testing.T) {
	const (
		Filename        = "./testdata/efs.yml"
		MasterKeyPath   = "./kes-master-key"
		MasterKeyCipher = "master-key-cipher"
		FSPath          = "/tmp/keys"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	fs, ok := config.KeyStore.(*EncryptedFSKeyStore)
	if !ok {
		var want *EncryptedFSKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if fs.MasterKeyPath != MasterKeyPath {
		t.Fatalf("Invalid keystore: got master key path '%s' - want path '%s'", fs.MasterKeyPath, MasterKeyPath)
	}
	if fs.MasterKeyCipher != MasterKeyCipher {
		t.Fatalf("Invalid keystore: got master key cipher '%s' - want cipher '%s'", fs.MasterKeyCipher, MasterKeyCipher)
	}
	if fs.Path != FSPath {
		t.Fatalf("Invalid keystore: got path '%s' - want path '%s'", fs.Path, FSPath)
	}
}

func TestReadServerConfigYAML_CustomAPI(t *testing.T) {
	const (
		Filename = "./testdata/custom-api.yml"

		StatusPath      = "/v1/status"
		StatusTimeout   = 17 * time.Second
		StatusSkipAuth  = true
		MetricsPath     = "/v1/metrics"
		MetricsTimeout  = 22 * time.Second
		MetricsSkipAuth = true
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	api, ok := config.API.Paths[StatusPath]
	if !ok {
		t.Fatalf("Invalid API config: missing API '%s'", StatusPath)
	}
	if api.Timeout != StatusTimeout {
		t.Fatalf("Invalid API config: invalid timeout for '%s': got '%v' - want '%v'", StatusPath, api.Timeout, StatusTimeout)
	}
	if api.InsecureSkipAuth != StatusSkipAuth {
		t.Fatalf("Invalid API config: invalid skip_auth for '%s': got '%v' - want '%v'", StatusPath, api.InsecureSkipAuth, StatusSkipAuth)
	}

	api, ok = config.API.Paths[MetricsPath]
	if !ok {
		t.Fatalf("Invalid API config: missing API '%s'", MetricsPath)
	}
	if api.Timeout != MetricsTimeout {
		t.Fatalf("Invalid API config: invalid timeout for '%s': got '%v' - want '%v'", StatusPath, api.Timeout, MetricsTimeout)
	}
	if api.InsecureSkipAuth != MetricsSkipAuth {
		t.Fatalf("Invalid API config: invalid skip_auth for '%s': got '%v' - want '%v'", StatusPath, api.InsecureSkipAuth, MetricsSkipAuth)
	}
}

func TestReadServerConfigYAML_VaultWithAppRole(t *testing.T) {
	const (
		Filename = "./testdata/vault-approle.yml"

		Endpoint      = "https://127.0.0.1:8200"
		Engine        = "kv"
		APIVersion    = "v2"
		Namespace     = "ns1"
		Prefix        = "tenant-1"
		AppRoleEngine = "approle"
		AppRoleID     = "db02de05-fa39-4855-059b-67221c5c2f63"
		AppRoleSecret = "6a174c20-f6de-a53c-74d2-6018fcceff64"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	vault, ok := config.KeyStore.(*VaultKeyStore)
	if !ok {
		var want *VaultKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if vault.Endpoint != Endpoint {
		t.Fatalf("Invalid endpoint: got '%s' - want '%s'", vault.Endpoint, Endpoint)
	}
	if vault.Engine != Engine {
		t.Fatalf("Invalid engine: got '%s' - want '%s'", vault.Engine, Engine)
	}
	if vault.APIVersion != APIVersion {
		t.Fatalf("Invalid API version: got '%s' - want '%s'", vault.APIVersion, APIVersion)
	}
	if vault.Namespace != Namespace {
		t.Fatalf("Invalid namespace: got '%s' - want '%s'", vault.Namespace, Namespace)
	}
	if vault.AppRole.Engine != AppRoleEngine {
		t.Fatalf("Invalid approle engine: got '%s' - want '%s'", vault.AppRole.Engine, AppRoleEngine)
	}
	if vault.AppRole.ID != AppRoleID {
		t.Fatalf("Invalid approle ID: got '%s' - want '%s'", vault.AppRole.ID, AppRoleID)
	}
	if vault.AppRole.Secret != AppRoleSecret {
		t.Fatalf("Invalid approle secret: got '%s' - want '%s'", vault.AppRole.Secret, AppRoleSecret)
	}
}

func TestReadServerConfigYAML_VaultWithK8S(t *testing.T) {
	const (
		Filename = "./testdata/vault-k8s.yml"

		Endpoint   = "https://127.0.0.1:8201"
		Engine     = "secrets"
		APIVersion = "v1"
		Namespace  = "ns2"
		Prefix     = "tenant-2"
		K8SEngine  = "kubernetes"
		K8SRole    = "default"
		K8SJWT     = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJQbGNNeTdBeXdLQmZMaGw2N1dFZkJvUmtsdnVvdkxXWGsteTc5TmJPeGMifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteS1uYW1lc3BhY2UiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoibXktc2VydmljZS1hY2NvdW50LXRva2VuLXA5NWRyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6Im15LXNlcnZpY2UtYWNjb3VudCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdiYmViZGE2LTViMDUtNGFlNC05Yjg2LTBkODE0NWMwNzdhNSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpteS1uYW1lc3BhY2U6bXktc2VydmljZS1hY2NvdW50In0.dnvJE3LU7L8XxsIOwea3lUZAULdwAjV9_crHFLKBGNxEu70lk3MQmUbGTEFvawryArmxMa1bWF9wbK1GHEsNipDgWAmc0rmBYByP_ahlf9bI2EEzpaGU5s194csB_eG7kvfi1AHED_nkVTfvCjIJM-9oGICCjDJcoNOP1NAXICFmqvWfXl6SY3UoZvtzUOcH9-0hbARY3p6V5pPecW4Dm-yGub9PKZLJNzv7GxChM-uvBvHAt6o0UBIL4iSy6Bx2l91ojB-RSkm_oy0W9gKi9ZFQPgyvcvQnEfjoGdvNGlOEdFEdXvl-dP6iLBPnZ5xwhAk8lK0oOONWvQg6VDNd9w"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	vault, ok := config.KeyStore.(*VaultKeyStore)
	if !ok {
		var want *VaultKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if vault.Endpoint != Endpoint {
		t.Fatalf("Invalid endpoint: got '%s' - want '%s'", vault.Endpoint, Endpoint)
	}
	if vault.Engine != Engine {
		t.Fatalf("Invalid engine: got '%s' - want '%s'", vault.Engine, Engine)
	}
	if vault.APIVersion != APIVersion {
		t.Fatalf("Invalid API version: got '%s' - want '%s'", vault.APIVersion, APIVersion)
	}
	if vault.Namespace != Namespace {
		t.Fatalf("Invalid namespace: got '%s' - want '%s'", vault.Namespace, Namespace)
	}
	if vault.Kubernetes.Engine != K8SEngine {
		t.Fatalf("Invalid K8S engine: got '%s' - want '%s'", vault.Kubernetes.Engine, K8SEngine)
	}
	if vault.Kubernetes.JWT != K8SJWT {
		t.Fatalf("Invalid K8S JWT: got '%s' - want '%s'", vault.Kubernetes.JWT, K8SJWT)
	}
	if vault.Kubernetes.Role != K8SRole {
		t.Fatalf("Invalid K8S role: got '%s' - want '%s'", vault.Kubernetes.Role, K8SRole)
	}
}

func TestReadServerConfigYAML_VaultWithK8S_JWTFile(t *testing.T) {
	const (
		Filename = "./testdata/vault-k8s-with-service-account-file.yml"

		Endpoint   = "https://127.0.0.1:8201"
		Engine     = "secrets"
		APIVersion = "v1"
		Namespace  = "ns2"
		Prefix     = "tenant-2"
		K8SEngine  = "kubernetes"
		K8SRole    = "default"
		K8SJWTFile = "./testdata/vault-k8s-service-account"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	vault, ok := config.KeyStore.(*VaultKeyStore)
	if !ok {
		var want *VaultKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if vault.Endpoint != Endpoint {
		t.Fatalf("Invalid endpoint: got '%s' - want '%s'", vault.Endpoint, Endpoint)
	}
	if vault.Engine != Engine {
		t.Fatalf("Invalid engine: got '%s' - want '%s'", vault.Engine, Engine)
	}
	if vault.APIVersion != APIVersion {
		t.Fatalf("Invalid API version: got '%s' - want '%s'", vault.APIVersion, APIVersion)
	}
	if vault.Namespace != Namespace {
		t.Fatalf("Invalid namespace: got '%s' - want '%s'", vault.Namespace, Namespace)
	}
	if vault.Kubernetes.Engine != K8SEngine {
		t.Fatalf("Invalid K8S engine: got '%s' - want '%s'", vault.Kubernetes.Engine, K8SEngine)
	}
	if vault.Kubernetes.JWT != K8SJWTFile {
		t.Fatalf("Invalid K8S JWT: got '%s' - want '%s'", vault.Kubernetes.JWT, K8SJWTFile)
	}
	if vault.Kubernetes.Role != K8SRole {
		t.Fatalf("Invalid K8S role: got '%s' - want'%s'", vault.Kubernetes.Role, K8SRole)
	}
}

func TestReadServerConfigYAML_AWS(t *testing.T) {
	const (
		Filename = "./testdata/aws.yml"

		Endpoint  = "secretsmanager.us-east-2.amazonaws.com"
		Region    = "us-east-2"
		AccessKey = "AKIAIOSFODNN7EXAMPLE"
		Secretkey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	aws, ok := config.KeyStore.(*AWSSecretsManagerKeyStore)
	if !ok {
		var want *AWSSecretsManagerKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if aws.Endpoint != Endpoint {
		t.Fatalf("Invalid endpoint: got '%s' - want '%s'", aws.Endpoint, Endpoint)
	}
	if aws.Region != Region {
		t.Fatalf("Invalid region: got '%s' - want '%s'", aws.Region, Region)
	}
	if aws.AccessKey != AccessKey {
		t.Fatalf("Invalid access key: got '%s' - want '%s'", aws.AccessKey, AccessKey)
	}
	if aws.SecretKey != Secretkey {
		t.Fatalf("Invalid secret key: got '%s' - want '%s'", aws.SecretKey, Secretkey)
	}
}

func TestReadServerConfigYAML_AWS_NoCredentials(t *testing.T) {
	// The AWS SDK will look for access credentials from the env.
	// when no credentials are specified in the config.

	const (
		Filename = "./testdata/aws-no-credentials.yml"

		Endpoint     = "secretsmanager.us-east-2.amazonaws.com"
		Region       = "us-east-2"
		AccessKey    = ""
		Secretkey    = ""
		SessionToken = ""
	)

	config, err := ReadFile(Filename)
	if err != nil {
		t.Fatalf("Failed to read file '%s': %v", Filename, err)
	}

	aws, ok := config.KeyStore.(*AWSSecretsManagerKeyStore)
	if !ok {
		var want *AWSSecretsManagerKeyStore
		t.Fatalf("Invalid keystore: got type '%T' - want type '%T'", config.KeyStore, want)
	}
	if aws.Endpoint != Endpoint {
		t.Fatalf("Invalid endpoint: got '%s' - want '%s'", aws.Endpoint, Endpoint)
	}
	if aws.Region != Region {
		t.Fatalf("Invalid region: got '%s' - want '%s'", aws.Region, Region)
	}
	if aws.AccessKey != AccessKey {
		t.Fatalf("Invalid access key: got '%s' - want '%s'", aws.AccessKey, AccessKey)
	}
	if aws.SecretKey != Secretkey {
		t.Fatalf("Invalid secret key: got '%s' - want '%s'", aws.SecretKey, Secretkey)
	}
	if aws.SessionToken != SessionToken {
		t.Fatalf("Invalid secret key: got '%s' - want '%s'", aws.SessionToken, SessionToken)
	}
}
