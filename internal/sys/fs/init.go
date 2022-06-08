// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fs

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/internal/yml"
	"gopkg.in/yaml.v3"
)

// SealConfig contains the initial seal configuration
// for a stateful KESdeployment.
type SealConfig struct {
	SysAdmin kes.Identity

	Sealer sys.Sealer
}

// InitConfig contains the initial configuration for
// a stateful KES deployment.
type InitConfig struct {
	Version string

	Address yml.String

	PrivateKey yml.String

	Certificate yml.String

	Password yml.String

	VerifyClientCerts yml.Bool
}

// ReadInitConfig reads and parses the InitConfig YAML representation
// from the given file.
func ReadInitConfig(filename string) (*InitConfig, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type YAML struct {
		Version string `yaml:"version"`

		Address yml.String `yaml:"address"`

		TLS struct {
			PrivateKey  yml.String `yaml:"key"`
			Certificate yml.String `yaml:"cert"`
			Password    yml.String `yaml:"password"`
			Client      struct {
				VerifyCerts yml.Bool `yaml:"verify_cert"`
			} `yaml:"client"`
		} `yaml:"tls"`
	}
	var config YAML
	if err := yaml.NewDecoder(f).Decode(&config); err != nil {
		return nil, err
	}
	if config.Version != "1" {
		return nil, fmt.Errorf("fs: config version '%s' is not supported", config.Version)
	}
	if config.Address.Value() == "" {
		config.Address.Set("[::]:7373")
	}
	return &InitConfig{
		Address:           config.Address,
		PrivateKey:        config.TLS.PrivateKey,
		Certificate:       config.TLS.Certificate,
		Password:          config.TLS.Password,
		VerifyClientCerts: config.TLS.Client.VerifyCerts,
	}, nil
}

// WriteInitConfig writes the YAML representation of the given
// InitConfig to a file.
func WriteInitConfig(filename string, config *InitConfig) error {
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	type YAML struct {
		Version string `yaml:"version"`

		Address yml.String `yaml:"address"`

		TLS struct {
			PrivateKey  yml.String `yaml:"key"`
			Certificate yml.String `yaml:"cert"`
			Password    yml.String `yaml:"password"`
			Client      struct {
				VerifyCerts yml.Bool `yaml:"verify_cert"`
			} `yaml:"client"`
		} `yaml:"tls"`
	}

	c := YAML{
		Version: "1",
		Address: config.Address,
	}
	c.TLS.PrivateKey = config.PrivateKey
	c.TLS.Certificate = config.Certificate
	c.TLS.Password = config.Password
	c.TLS.Client.VerifyCerts = config.VerifyClientCerts
	return yaml.NewEncoder(f).Encode(c)
}

// Init initializes a stateful KES deployment within the given
// path using the InitConfig and SealConfig.
//
// It returns an initialized Vault and a set of UnsealKeys to
// unseal the Vault in the future.
func Init(path string, init *InitConfig, seal *SealConfig) (sys.Vault, []sys.UnsealKey, error) {
	algorithm := key.AES256_GCM_SHA256
	if !fips.Enabled && !cpu.HasAESGCM() {
		algorithm = key.XCHACHA20_POLY1305
	}
	rootKey, err := key.Random(algorithm, seal.SysAdmin)
	if err != nil {
		return nil, nil, err
	}

	if err := initFS(path); err != nil {
		return nil, nil, err
	}
	if err := WriteInitConfig(filepath.Join(path, ".init"), init); err != nil {
		return nil, nil, err
	}
	unsealKeys, err := initSeal(path, rootKey, seal.Sealer)
	if err != nil {
		return nil, nil, err
	}
	return &vault{
		path:     path,
		rootKey:  rootKey,
		sysAdmin: rootKey.CreatedBy(),
		enclaves: map[string]*sys.Enclave{},
	}, unsealKeys, nil
}

// Open returns a new Vault that reads its initial and seal configuration
// from config files within the given path.
func Open(path string, errorLog *log.Logger) (sys.Vault, error) {
	stanzaBytes, err := os.ReadFile(filepath.Join(path, ".unseal"))
	if err != nil {
		return nil, err
	}
	var stanza sys.Stanza
	if err = stanza.UnmarshalBinary(stanzaBytes); err != nil {
		return nil, err
	}
	rootKeyBytes, err := sys.UnsealFromEnvironment().Unseal(&stanza)
	if err != nil {
		return nil, err
	}
	var rootKey key.Key
	if err := rootKey.UnmarshalBinary(rootKeyBytes); err != nil {
		return nil, err
	}
	return &vault{
		path:     path,
		rootKey:  rootKey,
		sysAdmin: rootKey.CreatedBy(),
		enclaves: map[string]*sys.Enclave{},
		errorLog: errorLog,
	}, nil
}

func initFS(path string) error {
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return os.ErrExist
		}
		return err
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	return nil
}

func initSeal(path string, key key.Key, sealer sys.Sealer) ([]sys.UnsealKey, error) {
	keyBytes, err := key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	stanza, unsealKeys, err := sealer.Seal(keyBytes)
	if err != nil {
		return nil, err
	}
	stanzaBytes, err := stanza.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(path, ".unseal"), stanzaBytes, 0o600); err != nil {
		return nil, err
	}
	return unsealKeys, nil
}
