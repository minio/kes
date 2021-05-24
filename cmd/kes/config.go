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
	"github.com/minio/kes/internal/generic"
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

	Policies map[string]policyConfig `yaml:"policy"`

	Cache struct {
		Expiry struct {
			Any    duration `yaml:"any"`    // Use custom type for env. var support
			Unused duration `yaml:"unused"` // Use custom type for env. var support
		} `yaml:"expiry"`
	} `yaml:"cache"`

	Log struct {
		Error string `yaml:"error"`
		Audit string `yaml:"audit"`
	} `yaml:"log"`

	Keys []struct {
		Name string `yaml:"name"`
	} `yaml:"keys"`

	KeyStore kmsServerConfig `yaml:"keystore"`
}

func loadServerConfig(path string) (config serverConfig, err error) {
	if path == "" {
		return config, nil
	}

	b, err := ioutil.ReadFile(path)
	if err != nil {
		return config, err
	}
	if err = yaml.UnmarshalStrict(b, &config); err != nil {
		if _, ok := err.(*yaml.TypeError); !ok {
			return config, err
		}

		var configV0140 serverConfigV0140
		if errV0140 := yaml.Unmarshal(b, &configV0140); errV0140 == nil {
			config = configV0140.Migrate()
		} else {
			if _, ok := errV0140.(*yaml.TypeError); !ok {
				return config, err // return the actual unmarshal error on purpose
			}

			var configV0135 serverConfigV0135
			if yaml.Unmarshal(b, &configV0135) != nil {
				return config, err // return the actual unmarshal error on purpose
			}
			config = configV0135.Migrate()
		}
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

	for i, key := range config.Keys {
		config.Keys[i].Name = expandEnv(key.Name)
	}

	// FS backend
	config.KeyStore.Fs.Path = expandEnv(config.KeyStore.Fs.Path)

	// Hashicorp Vault backend
	config.KeyStore.Vault.Endpoint = expandEnv(config.KeyStore.Vault.Endpoint)
	config.KeyStore.Vault.EnginePath = expandEnv(config.KeyStore.Vault.EnginePath)
	config.KeyStore.Vault.Namespace = expandEnv(config.KeyStore.Vault.Namespace)
	config.KeyStore.Vault.Prefix = expandEnv(config.KeyStore.Vault.Prefix)
	config.KeyStore.Vault.AppRole.EnginePath = expandEnv(config.KeyStore.Vault.AppRole.EnginePath)
	config.KeyStore.Vault.AppRole.ID = expandEnv(config.KeyStore.Vault.AppRole.ID)
	config.KeyStore.Vault.AppRole.Secret = expandEnv(config.KeyStore.Vault.AppRole.Secret)
	config.KeyStore.Vault.Kubernetes.EnginePath = expandEnv(config.KeyStore.Vault.Kubernetes.EnginePath)
	config.KeyStore.Vault.Kubernetes.JWT = expandEnv(config.KeyStore.Vault.Kubernetes.JWT)
	config.KeyStore.Vault.Kubernetes.Role = expandEnv(config.KeyStore.Vault.Kubernetes.Role)
	config.KeyStore.Vault.TLS.KeyPath = expandEnv(config.KeyStore.Vault.TLS.KeyPath)
	config.KeyStore.Vault.TLS.CertPath = expandEnv(config.KeyStore.Vault.TLS.CertPath)
	config.KeyStore.Vault.TLS.CAPath = expandEnv(config.KeyStore.Vault.TLS.CAPath)

	// AWS SecretsManager backend
	config.KeyStore.Aws.SecretsManager.Endpoint = expandEnv(config.KeyStore.Aws.SecretsManager.Endpoint)
	config.KeyStore.Aws.SecretsManager.Region = expandEnv(config.KeyStore.Aws.SecretsManager.Region)
	config.KeyStore.Aws.SecretsManager.KmsKey = expandEnv(config.KeyStore.Aws.SecretsManager.KmsKey)
	config.KeyStore.Aws.SecretsManager.Login.AccessKey = expandEnv(config.KeyStore.Aws.SecretsManager.Login.AccessKey)
	config.KeyStore.Aws.SecretsManager.Login.SecretKey = expandEnv(config.KeyStore.Aws.SecretsManager.Login.SecretKey)
	config.KeyStore.Aws.SecretsManager.Login.SessionToken = expandEnv(config.KeyStore.Aws.SecretsManager.Login.SessionToken)

	// Gemalto KeySecure backend
	config.KeyStore.Gemalto.KeySecure.Endpoint = expandEnv(config.KeyStore.Gemalto.KeySecure.Endpoint)
	config.KeyStore.Gemalto.KeySecure.TLS.CAPath = expandEnv(config.KeyStore.Gemalto.KeySecure.TLS.CAPath)
	config.KeyStore.Gemalto.KeySecure.Login.Domain = expandEnv(config.KeyStore.Gemalto.KeySecure.Login.Domain)
	config.KeyStore.Gemalto.KeySecure.Login.Token = expandEnv(config.KeyStore.Gemalto.KeySecure.Login.Token)

	// GCP SecretManager backend
	config.KeyStore.GCP.SecretManager.ProjectID = expandEnv(config.KeyStore.GCP.SecretManager.ProjectID)
	config.KeyStore.GCP.SecretManager.Endpoint = expandEnv(config.KeyStore.GCP.SecretManager.Endpoint)
	config.KeyStore.GCP.SecretManager.Credentials.Client = expandEnv(config.KeyStore.GCP.SecretManager.Credentials.Client)
	config.KeyStore.GCP.SecretManager.Credentials.ClientID = expandEnv(config.KeyStore.GCP.SecretManager.Credentials.ClientID)
	config.KeyStore.GCP.SecretManager.Credentials.Key = expandEnv(config.KeyStore.GCP.SecretManager.Credentials.Key)
	config.KeyStore.GCP.SecretManager.Credentials.KeyID = expandEnv(config.KeyStore.GCP.SecretManager.Credentials.KeyID)

	// We handle the Hashicorp Vault Kubernetes JWT specially
	// since it can either be specified directly or be mounted
	// as a file (K8S secret).
	// Therefore, we check whether the JWT field is a file, and if so,
	// read the JWT from there.
	if config.KeyStore.Vault.Kubernetes.JWT != "" {
		f, err := os.Open(config.KeyStore.Vault.Kubernetes.JWT)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return config, fmt.Errorf("failed to open Vault Kubernetes JWT: %v", err)
		}
		if err == nil {
			jwt, err := ioutil.ReadAll(f)
			if err != nil {
				return config, fmt.Errorf("failed to read Vault Kubernetes JWT: %v", err)
			}
			config.KeyStore.Vault.Kubernetes.JWT = string(jwt)
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
	config.KeyStore.SetDefaults()
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
	return config.KeyStore.Verify()
}

type policyConfig struct {
	Allow      []string       `yaml:"allow"`
	Deny       []string       `yaml:"deny"`
	Identities []kes.Identity `yaml:"identities"`
}

type kmsServerConfig struct {
	Fs struct {
		Path string `yaml:"path"`
	} `yaml:"fs"`

	Generic struct {
		Endpoint string `yaml:"endpoint"`
		TLS      struct {
			KeyPath  string `yaml:"key"`
			CertPath string `yaml:"cert"`
			CAPath   string `yaml:"ca"`
		} `yaml:"tls"`
	} `yaml:"generic"`

	Vault struct {
		Endpoint   string `yaml:"endpoint"`
		EnginePath string `yaml:"engine"`
		Namespace  string `yaml:"namespace"`

		Prefix string `yaml:"prefix"`

		AppRole struct {
			EnginePath string   `yaml:"engine"`
			ID         string   `yaml:"id"`
			Secret     string   `yaml:"secret"`
			Retry      duration `yaml:"retry"` // Use custom type for env. var support
		} `yaml:"approle"`

		Kubernetes struct {
			EnginePath string   `yaml:"engine"`
			Role       string   `yaml:"role"`
			JWT        string   `yaml:"jwt"`   // Can be either a JWT or a path to a file containing a JWT
			Retry      duration `yaml:"retry"` // Use custom type for env. var support
		} `yaml:"kubernetes"`

		TLS struct {
			KeyPath  string `yaml:"key"`
			CertPath string `yaml:"cert"`
			CAPath   string `yaml:"ca"`
		} `yaml:"tls"`

		Status struct {
			Ping duration `yaml:"ping"` // Use custom type for env. var support
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
				Token  string   `yaml:"token"`
				Domain string   `yaml:"domain"`
				Retry  duration `yaml:"retry"` // Use custom type for env. var support
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
	case config.Fs.Path != "" && config.Generic.Endpoint != "":
		return errors.New("ambiguous configuration: FS and Generic endpoint specified at the same time")
	case config.Fs.Path != "" && config.Vault.Endpoint != "":
		return errors.New("ambiguous configuration: FS and Hashicorp Vault endpoint specified at the same time")
	case config.Fs.Path != "" && config.Aws.SecretsManager.Endpoint != "":
		return errors.New("ambiguous configuration: FS and AWS Secrets Manager endpoint are specified at the same time")
	case config.Fs.Path != "" && config.Gemalto.KeySecure.Endpoint != "":
		return errors.New("ambiguous configuration: FS and Gemalto KeySecure endpoint are specified at the same time")
	case config.Fs.Path != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: FS and GCP secret manager are specified at the same time")
	case config.Generic.Endpoint != "" && config.Vault.Endpoint != "":
		return errors.New("ambiguous configuration: Generic and Hashicorp Vault endpoint are specified at the same time")
	case config.Generic.Endpoint != "" && config.Aws.SecretsManager.Endpoint != "":
		return errors.New("ambiguous configuration: Generic and AWS SecretsManager endpoint are specified at the same time")
	case config.Generic.Endpoint != "" && config.Gemalto.KeySecure.Endpoint != "":
		return errors.New("ambiguous configuration: Generic and Gemalto KeySecure endpoint are specified at the same time")
	case config.Generic.Endpoint != "" && config.GCP.SecretManager.ProjectID != "":
		return errors.New("ambiguous configuration: Generic and GCP SecretManager endpoint are specified at the same time")
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
	case config.Generic.Endpoint != "":
		genericStore := &generic.Store{
			Endpoint: config.Generic.Endpoint,
			KeyPath:  config.Generic.TLS.KeyPath,
			CertPath: config.Generic.TLS.CertPath,
			CAPath:   config.Generic.TLS.CAPath,
			ErrorLog: errorLog,
		}
		msg := fmt.Sprintf("Authenticating to generic KeyStore '%s' ... ", config.Generic.Endpoint)
		quiet.Print(msg)
		if err := genericStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to generic KeyStore: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = genericStore
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
				Retry:  time.Duration(config.Vault.AppRole.Retry),
			},
			K8S: vault.Kubernetes{
				Engine: config.Vault.Kubernetes.EnginePath,
				Role:   config.Vault.Kubernetes.Role,
				JWT:    config.Vault.Kubernetes.JWT,
				Retry:  time.Duration(config.Vault.Kubernetes.Retry),
			},
			StatusPingAfter: time.Duration(config.Vault.Status.Ping),
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
				Retry:  time.Duration(config.Gemalto.KeySecure.Login.Retry),
			},
		}

		msg := fmt.Sprintf("Authenticating to Gemalto KeySecure '%s' ... ", gemaltoStore.Endpoint)
		quiet.Print(msg)
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
	case config.Generic.Endpoint != "":
		kind = "Generic"
		endpoint = config.Generic.Endpoint
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
