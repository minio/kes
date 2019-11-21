package main

import (
	"os"
	"time"

	"github.com/aead/key"
	"github.com/pelletier/go-toml"
)

type serverConfig struct {
	Addr string       `toml:"address"`
	Root key.Identity `toml:"root"`

	TLS struct {
		KeyPath  string `toml:"key"`
		CertPath string `toml:"cert"`
	} `toml:"tls"`

	Policies map[string]struct {
		Paths      []string       `toml:"paths"`
		Identities []key.Identity `toml:"identities"`
	} `toml:"policy"`

	Vault struct {
		Addr string `toml:"address"`
		Name string `toml:"name"`

		AppRole struct {
			ID     string        `toml:"id"`
			Secret string        `toml:"secret"`
			Retry  time.Duration `toml:"retry"`
		} `toml:"approle"`

		Status struct {
			Ping time.Duration `toml:"ping"`
		} `toml:"status"`
	} `toml:"vault"`
}

func loadServerConfig(path string) (*serverConfig, error) {
	var config serverConfig

	// Set config defaults
	config.Vault.AppRole.Retry = 15 * time.Second
	config.Vault.Status.Ping = 10 * time.Second

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if err = toml.NewDecoder(file).Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}
