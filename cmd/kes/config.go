// Copyright 2019 - MinIO, Inc. All rights reserved.
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
	"github.com/minio/kes/internal/fs"
	"github.com/minio/kes/internal/gcp"
	"github.com/minio/kes/internal/gemalto"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/secret"
	"github.com/minio/kes/internal/vault"
	"gopkg.in/yaml.v2"
)

type serverConfig struct {
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

	Policies map[string]struct {
		Paths      []string       `yaml:"paths"`
		Identities []kes.Identity `yaml:"identities"`
	} `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any    time.Duration `yaml:"any"`
			Unused time.Duration `yaml:"unused"`
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error string `yaml:"error"`
		Audit string `yaml:"audit"`
	} `yaml:"log"`

	Keys kmsServerConfig `yaml:"keys"`
}

func loadServerConfig(path string) (config serverConfig, err error) {
	if path == "" {
		return config, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return config, err
	}
	decoder := yaml.NewDecoder(file)
	decoder.SetStrict(true) // Reject unknown fields in the config file
	if err = decoder.Decode(&config); err != nil {
		file.Close()
		return config, err
	}
	if err = file.Close(); err != nil {
		return config, err
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
	// We don't replace any durations - e.g. cache expiry - and policy paths.
	// Especially replacing policy paths is quite dangerous since it would not
	// be obvious which operations are allowed by a policy.
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

	// FS backend
	config.Keys.Fs.Path = expandEnv(config.Keys.Fs.Path)

	// Hashicorp Vault backend
	config.Keys.Vault.Endpoint = expandEnv(config.Keys.Vault.Endpoint)
	config.Keys.Vault.EnginePath = expandEnv(config.Keys.Vault.EnginePath)
	config.Keys.Vault.Namespace = expandEnv(config.Keys.Vault.Namespace)
	config.Keys.Vault.Prefix = expandEnv(config.Keys.Vault.Prefix)
	config.Keys.Vault.AppRole.EnginePath = expandEnv(config.Keys.Vault.AppRole.EnginePath)
	config.Keys.Vault.AppRole.ID = expandEnv(config.Keys.Vault.AppRole.ID)
	config.Keys.Vault.AppRole.Secret = expandEnv(config.Keys.Vault.AppRole.Secret)
	config.Keys.Vault.Kubernetes.EnginePath = expandEnv(config.Keys.Vault.Kubernetes.EnginePath)
	config.Keys.Vault.Kubernetes.JWT = expandEnv(config.Keys.Vault.Kubernetes.JWT)
	config.Keys.Vault.Kubernetes.Role = expandEnv(config.Keys.Vault.Kubernetes.Role)
	config.Keys.Vault.TLS.KeyPath = expandEnv(config.Keys.Vault.TLS.KeyPath)
	config.Keys.Vault.TLS.CertPath = expandEnv(config.Keys.Vault.TLS.CertPath)
	config.Keys.Vault.TLS.CAPath = expandEnv(config.Keys.Vault.TLS.CAPath)

	// AWS SecretsManager backend
	config.Keys.Aws.SecretsManager.Endpoint = expandEnv(config.Keys.Aws.SecretsManager.Endpoint)
	config.Keys.Aws.SecretsManager.Region = expandEnv(config.Keys.Aws.SecretsManager.Region)
	config.Keys.Aws.SecretsManager.KmsKey = expandEnv(config.Keys.Aws.SecretsManager.KmsKey)
	config.Keys.Aws.SecretsManager.Login.AccessKey = expandEnv(config.Keys.Aws.SecretsManager.Login.AccessKey)
	config.Keys.Aws.SecretsManager.Login.SecretKey = expandEnv(config.Keys.Aws.SecretsManager.Login.SecretKey)
	config.Keys.Aws.SecretsManager.Login.SessionToken = expandEnv(config.Keys.Aws.SecretsManager.Login.SessionToken)

	// Gemalto KeySecure backend
	config.Keys.Gemalto.KeySecure.Endpoint = expandEnv(config.Keys.Gemalto.KeySecure.Endpoint)
	config.Keys.Gemalto.KeySecure.TLS.CAPath = expandEnv(config.Keys.Gemalto.KeySecure.TLS.CAPath)
	config.Keys.Gemalto.KeySecure.Login.Domain = expandEnv(config.Keys.Gemalto.KeySecure.Login.Domain)
	config.Keys.Gemalto.KeySecure.Login.Token = expandEnv(config.Keys.Gemalto.KeySecure.Login.Token)

	// GCP SecretManager backend
	config.Keys.GCP.SecretManager.ProjectID = expandEnv(config.Keys.GCP.SecretManager.ProjectID)
	config.Keys.GCP.SecretManager.Endpoint = expandEnv(config.Keys.GCP.SecretManager.Endpoint)
	config.Keys.GCP.SecretManager.Credentials.Client = expandEnv(config.Keys.GCP.SecretManager.Credentials.Client)
	config.Keys.GCP.SecretManager.Credentials.ClientID = expandEnv(config.Keys.GCP.SecretManager.Credentials.ClientID)
	config.Keys.GCP.SecretManager.Credentials.Key = expandEnv(config.Keys.GCP.SecretManager.Credentials.Key)
	config.Keys.GCP.SecretManager.Credentials.KeyID = expandEnv(config.Keys.GCP.SecretManager.Credentials.KeyID)

	// We handle the Hashicorp Vault Kubernetes JWT specially
	// since it can either be specified directly or be mounted
	// as a file (K8S secret).
	// Therefore, we check whether the JWT field is a file, and if so,
	// read the JWT from there.
	if config.Keys.Vault.Kubernetes.JWT != "" {
		f, err := os.Open(config.Keys.Vault.Kubernetes.JWT)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return config, fmt.Errorf("failed to open Vault Kubernetes JWT: %v", err)
		}
		if err == nil {
			jwt, err := ioutil.ReadAll(f)
			if err != nil {
				return config, fmt.Errorf("failed to read Vault Kubernetes JWT: %v", err)
			}
			config.Keys.Vault.Kubernetes.JWT = string(jwt)
		}
	}
	return config, nil
}

// SetDefaults set default values for fields that may be empty b/c not specified by user.
func (config *serverConfig) SetDefaults() {
	if config.Log.Audit == "" {
		config.Log.Audit = "off" // If not set, default is off.
	}
	if config.Log.Error == "" {
		config.Log.Error = "on" // If not set, default is on.
	}
	config.Keys.SetDefaults()
}

// Verify checks whether the serverConfig contains invalid entries, and if so,
// returns an error.
func (config *serverConfig) Verify() error {
	if config.Root.IsUnknown() {
		return errors.New("no root identity has been specified")
	}
	if config.TLS.KeyPath == "" {
		return errors.New("no private key file has been specified")
	}
	if config.TLS.CertPath == "" {
		return errors.New("no certificate file has been specified")
	}

	for i, identity := range config.TLS.Proxy.Identities {
		if identity == config.Root {
			return fmt.Errorf("The %d-th TLS proxy identity is equal to the root identity %q. The root identity cannot be used as TLS proxy", i, identity)
		}
	}

	if v := strings.ToLower(config.Log.Audit); v != "on" && v != "off" {
		return fmt.Errorf("%q is an invalid audit log configuration", v)
	}
	if v := strings.ToLower(config.Log.Error); v != "on" && v != "off" {
		return fmt.Errorf("%q is an invalid error log configuration", v)
	}
	return config.Keys.Verify()
}

type kmsServerConfig struct {
	Fs struct {
		Path string `yaml:"path"`
	} `yaml:"fs"`

	Vault struct {
		Endpoint   string `yaml:"endpoint"`
		EnginePath string `yaml:"engine"`
		Namespace  string `yaml:"namespace"`

		Prefix string `yaml:"prefix"`

		AppRole struct {
			EnginePath string        `yaml:"engine"`
			ID         string        `yaml:"id"`
			Secret     string        `yaml:"secret"`
			Retry      time.Duration `yaml:"retry"`
		} `yaml:"approle"`

		Kubernetes struct {
			EnginePath string        `yaml:"engine"`
			Role       string        `yaml:"role"`
			JWT        string        `yaml:"jwt"` // Can be either a JWT or a path to a file containing a JWT
			Retry      time.Duration `yaml:"retry"`
		} `yaml:"kubernetes"`

		TLS struct {
			KeyPath  string `yaml:"key"`
			CertPath string `yaml:"cert"`
			CAPath   string `yaml:"ca"`
		} `yaml:"tls"`

		Status struct {
			Ping time.Duration `yaml:"ping"`
		} `yaml:"status"`
	} `yaml:"vault"`

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

	Gemalto struct {
		KeySecure struct {
			Endpoint string `yaml:"endpoint"`

			Login struct {
				Token  string        `yaml:"token"`
				Domain string        `yaml:"domain"`
				Retry  time.Duration `yaml:"retry"`
			} `yaml:"credentials"`

			TLS struct {
				CAPath string `yaml:"ca"`
			} `yaml:"tls"`
		} `yaml:"keysecure"`
	} `yaml:"gemalto"`

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
}

// SetDefaults set default values for fields that may be empty b/c not specified by user.
func (config *kmsServerConfig) SetDefaults() {
	if config.Vault.EnginePath == "" {
		config.Vault.EnginePath = "kv" // If not set, use the Vault default engine path.
	}
	if config.Vault.AppRole.EnginePath == "" {
		config.Vault.AppRole.EnginePath = "approle" // If not set, use the Vault default auth path for AppRole.
	}
	if config.Vault.Kubernetes.EnginePath == "" {
		config.Vault.Kubernetes.EnginePath = "kubernetes" // If not set, use the Vault default auth path for Kubernetes.
	}
	if config.GCP.SecretManager.ProjectID != "" && config.GCP.SecretManager.Endpoint == "" {
		config.GCP.SecretManager.Endpoint = "secretmanager.googleapis.com:443"
	}
}

// Verify checks whether the kmsServerConfig contains invalid entries, and if so,
// returns an error.
func (config *kmsServerConfig) Verify() error {
	switch {
	case config.Fs.Path != "" && config.Vault.Endpoint != "":
		return errors.New("ambiguous configuration: FS and Hashicorp Vault endpoint specified at the same time")
	case config.Fs.Path != "" && config.Aws.SecretsManager.Endpoint != "":
		return errors.New("ambiguous configuration: FS and AWS Secrets Manager endpoint are specified at the same time")
	case config.Fs.Path != "" && config.Gemalto.KeySecure.Endpoint != "":
		return errors.New("ambiguous configuration: FS and Gemalto KeySecure endpoint are specified at the same time")
	case config.Fs.Path != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: FS and GCP secret manager are specified at the same time")
	case config.Vault.Endpoint != "" && config.Aws.SecretsManager.Endpoint != "":
		return errors.New("ambiguous configuration: Hashicorp Vault and AWS SecretsManager endpoint are specified at the same time")
	case config.Vault.Endpoint != "" && config.Gemalto.KeySecure.Endpoint != "":
		return errors.New("ambiguous configuration: Hashicorp Vault and Gemalto KeySecure endpoint are specified at the same time")
	case config.Vault.Endpoint != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: Hashicorp Vault and GCP secret manager are specified at the same time")
	case config.Aws.SecretsManager.Endpoint != "" && config.Gemalto.KeySecure.Endpoint != "":
		return errors.New("ambiguous configuration: AWS SecretsManager and Gemalto KeySecure endpoint are specified at the same time")
	case config.Aws.SecretsManager.Endpoint != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: AWS SecretsManager and GCP secret manager are specified at the same time")
	case config.Gemalto.KeySecure.Endpoint != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: Gemalto KeySecure endpoint and GCP secret manager are specified at the same time")
	}

	if config.Vault.Endpoint != "" {
		approle, k8s := config.Vault.AppRole, config.Vault.Kubernetes
		if (approle.ID != "" || approle.Secret != "") && (k8s.Role != "" || k8s.JWT != "") {
			return errors.New("invalid configuration: Vault AppRole and Kubernetes credentials are specified at the same time")
		}
	}
	return nil
}

// Connect tries to establish a connection to the KMS specified in the kmsServerConfig.
func (config *kmsServerConfig) Connect(quiet quiet, errorLog *stdlog.Logger) (*secret.Store, error) {
	if err := config.Verify(); err != nil {
		return nil, err
	}

	var store secret.Store
	switch {
	case config.Fs.Path != "":
		f, err := os.Stat(config.Fs.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to open %q: %v", config.Fs.Path, err)
		}
		if err == nil && !f.IsDir() {
			return nil, fmt.Errorf("%q is not a directory", config.Fs.Path)
		}
		if errors.Is(err, os.ErrNotExist) {
			msg := fmt.Sprintf("Creating directory '%s' ... ", config.Fs.Path)
			quiet.Print(msg)
			if err = os.MkdirAll(config.Fs.Path, 0700); err != nil {
				return nil, fmt.Errorf("failed to create directory %q: %v", config.Fs.Path, err)
			}
			quiet.ClearMessage(msg)
		}
		store.Remote = &fs.Store{
			Dir:      config.Fs.Path,
			ErrorLog: errorLog,
		}
	case config.Vault.Endpoint != "":
		vaultStore := &vault.Store{
			Addr:      config.Vault.Endpoint,
			Engine:    config.Vault.EnginePath,
			Location:  config.Vault.Prefix,
			Namespace: config.Vault.Namespace,
			AppRole: vault.AppRole{
				Engine: config.Vault.AppRole.EnginePath,
				ID:     config.Vault.AppRole.ID,
				Secret: config.Vault.AppRole.Secret,
				Retry:  config.Vault.AppRole.Retry,
			},
			K8S: vault.Kubernetes{
				Engine: config.Vault.Kubernetes.EnginePath,
				Role:   config.Vault.Kubernetes.Role,
				JWT:    config.Vault.Kubernetes.JWT,
				Retry:  config.Vault.Kubernetes.Retry,
			},
			StatusPingAfter: config.Vault.Status.Ping,
			ErrorLog:        errorLog,
			ClientKeyPath:   config.Vault.TLS.KeyPath,
			ClientCertPath:  config.Vault.TLS.CertPath,
			CAPath:          config.Vault.TLS.CAPath,
		}

		msg := fmt.Sprintf("Authenticating to Hashicorp Vault '%s' ... ", vaultStore.Addr)
		quiet.Print(msg)
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to connect to Vault: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = vaultStore
	case config.Aws.SecretsManager.Endpoint != "":
		awsStore := &aws.SecretsManager{
			Addr:     config.Aws.SecretsManager.Endpoint,
			Region:   config.Aws.SecretsManager.Region,
			KMSKeyID: config.Aws.SecretsManager.KmsKey,
			ErrorLog: errorLog,
			Login: aws.Credentials{
				AccessKey:    config.Aws.SecretsManager.Login.AccessKey,
				SecretKey:    config.Aws.SecretsManager.Login.SecretKey,
				SessionToken: config.Aws.SecretsManager.Login.SessionToken,
			},
		}

		msg := fmt.Sprintf("Authenticating to AWS SecretsManager '%s' ... ", awsStore.Addr)
		quiet.Print(msg)
		if err := awsStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to AWS Secrets Manager: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = awsStore
	case config.Gemalto.KeySecure.Endpoint != "":
		gemaltoStore := &gemalto.KeySecure{
			Endpoint: config.Gemalto.KeySecure.Endpoint,
			CAPath:   config.Gemalto.KeySecure.TLS.CAPath,
			ErrorLog: errorLog,
			Login: gemalto.Credentials{
				Token:  config.Gemalto.KeySecure.Login.Token,
				Domain: config.Gemalto.KeySecure.Login.Domain,
				Retry:  config.Gemalto.KeySecure.Login.Retry,
			},
		}

		msg := fmt.Sprintf("Authenticating to Gemalto KeySecure '%s' ... ", gemaltoStore.Endpoint)
		quiet.Printf(msg)
		if err := gemaltoStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to Gemalto KeySecure: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = gemaltoStore
	case config.GCP.SecretManager.ProjectID != "":
		gcpStore := &gcp.SecretManager{
			Endpoint:  config.GCP.SecretManager.Endpoint,
			ProjectID: config.GCP.SecretManager.ProjectID,
			ErrorLog:  errorLog,
		}

		msg := fmt.Sprintf("Authenticating to GCP SecretManager Project: '%s' ... ", gcpStore.ProjectID)
		quiet.Print(msg)
		err := gcpStore.Authenticate(gcp.Credentials{
			ClientID: config.GCP.SecretManager.Credentials.ClientID,
			Client:   config.GCP.SecretManager.Credentials.Client,
			KeyID:    config.GCP.SecretManager.Credentials.KeyID,
			Key:      config.GCP.SecretManager.Credentials.Key,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to GCP SecretManager: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = gcpStore
	default:
		store.Remote = &mem.Store{}
	}
	return &store, nil
}

func (config *kmsServerConfig) Description() (kind, endpoint string, err error) {
	if err = config.Verify(); err != nil {
		return "", "", err
	}

	switch {
	case config.Fs.Path != "":
		kind = "Filesystem"
		if endpoint, err = filepath.Abs(config.Fs.Path); err != nil {
			endpoint = config.Fs.Path
		}
	case config.Vault.Endpoint != "":
		kind = "Hashicorp Vault"
		endpoint = config.Vault.Endpoint
	case config.Aws.SecretsManager.Endpoint != "":
		kind = "AWS SecretsManager"
		endpoint = config.Aws.SecretsManager.Endpoint
	case config.Gemalto.KeySecure.Endpoint != "":
		kind = "Gemalto KeySecure"
		endpoint = config.Gemalto.KeySecure.Endpoint
	case config.GCP.SecretManager.ProjectID != "":
		kind = "GCP SecretManager"
		endpoint = config.GCP.SecretManager.Endpoint + " | Project: " + config.GCP.SecretManager.ProjectID
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
