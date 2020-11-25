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

	// Replace identities that refer to env. variables with the
	// corresponding env. variable values.
	// An identity refers to an env. variable if it has the form:
	//  ${<env-var-name>}
	// We then replace the identity with the env. variable value.
	// Currently only identities can be customized via env. variables.
	if refersToEnvVar(config.Root.String()) {
		config.Root = kes.Identity(os.ExpandEnv(config.Root.String()))
	}
	for i, identity := range config.TLS.Proxy.Identities { // The TLS proxy identities section
		if refersToEnvVar(identity.String()) {
			config.TLS.Proxy.Identities[i] = kes.Identity(os.ExpandEnv(identity.String()))
		}
	}
	for _, policy := range config.Policies { // The policy section
		for i, identity := range policy.Identities {
			if refersToEnvVar(identity.String()) {
				policy.Identities[i] = kes.Identity(os.ExpandEnv(identity.String()))
			}
		}
	}
	return config, file.Close()
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
		config.Vault.AppRole.EnginePath = "approle" // If not set, use the Vault default auth path.
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
	default:
		return nil
	}
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

// refersToEnvVar returns true if s has the following form:
//  ${<env-var-name}
//
// In this case s should be replaced by the referenced
// env. variable.
//
// refersToEnvVar ignores any leading or trailing whitespaces.
func refersToEnvVar(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}")
}
