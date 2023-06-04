// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cluster

import (
	"errors"
	"fmt"

	"github.com/minio/kes-go"
)

type configYML struct {
	Version string `yaml:"version"`

	Addr string `yaml:"address"`

	Admin struct {
		Identity kes.Identity `yaml:"identity"`
	} `yaml:"admin"`

	TLS struct {
		PrivateKey  string `yaml:"key"`
		Certificate string `yaml:"cert"`
		CAPath      string `yaml:"ca"`
	}
}

func ymlToConfig(yml *configYML) (*ServerConfig, error) {
	if yml.Version != "v1" {
		return nil, fmt.Errorf("edge: invalid version '%s'", yml.Version)
	}
	if yml.Addr == "" {
		yml.Addr = "0.0.0.0:7373"
	}
	if yml.Admin.Identity.IsUnknown() {
		return nil, errors.New("kes: invalid admin identity: no admin identity")
	}
	return &ServerConfig{
		Admin: yml.Admin.Identity,
		TLS: &TLSConfig{
			PrivateKey:  yml.TLS.PrivateKey,
			Certificate: yml.TLS.Certificate,
			CAPath:      yml.TLS.CAPath,
		},
	}, nil
}
