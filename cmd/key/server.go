package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aead/key"
	"github.com/aead/key/kms/mem"
	"github.com/aead/key/kms/vault"
)

const serverCmdUsage = `usage: %s [options]

  --addr               The address of the server (default: 127.0.0.1:7373)
  --config             Path to the server configuration file
  --root               The identity of root - who can perform any operation.
                       A root identity must be specified - either via this 
                       flag or within the config file. This flag takes 
                       precedence over the config file.

  --tls-key            Path to the TLS private key. It takes precedence over
                       the config file. 
  --tls-cert           Path to the TLS certificate. It takes precedence over
                       the config file.
`

func server(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), serverCmdUsage, cli.Name())
	}

	var (
		addr         string
		configPath   string
		rootIdentity string

		tlsKeyPath  string
		tlsCertPath string
	)
	cli.StringVar(&addr, "addr", "127.0.0.1:7373", "The address of the server")
	cli.StringVar(&configPath, "config", "", "Path to the server configuration file")
	cli.StringVar(&rootIdentity, "root", "", "The identity of root - who can perform any operation")
	cli.StringVar(&tlsKeyPath, "tls-key", "", "Path to the TLS private key")
	cli.StringVar(&tlsCertPath, "tls-cert", "", "Path to the TLS certificate")
	cli.Parse(args[1:])

	if cli.NArg() != 0 {
		cli.Usage()
		os.Exit(2)
	}

	config, err := loadServerConfig(configPath)
	if err != nil {
		failf(cli.Output(), "Cannot read config file: %v", err)
	}
	if addr == "" {
		addr = config.Addr
	}
	if rootIdentity == "" {
		if config.Root == "" {
			failf(cli.Output(), "No root identity is present")
		}
		rootIdentity = string(config.Root)
	}
	if tlsKeyPath == "" {
		tlsKeyPath = config.TLS.KeyPath
	}
	if tlsCertPath == "" {
		tlsCertPath = config.TLS.CertPath
	}
	certificate, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
	if err != nil {
		failf(cli.Output(), "Failed to load TLS certificate: %v", err)
	}

	server := key.Server{
		Addr: addr,
		Roles: &key.Roles{
			Root: key.Identity(rootIdentity),
		},
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAnyClientCert,
			Certificates: []tls.Certificate{certificate},
		},
	}

	switch {
	case config.Vault.Addr != "":
		store, err := vault.NewKeyStore(&vault.Config{
			Addr: config.Vault.Addr,
			Name: config.Vault.Name,
			AppRole: vault.AppRole{
				ID:     config.Vault.AppRole.ID,
				Secret: config.Vault.AppRole.Secret,
				Retry:  config.Vault.AppRole.Retry,
			},
			StatusPing: config.Vault.Status.Ping,
		})
		if err != nil {
			failf(cli.Output(), "Failed to connect to Vault: %v", err)
		}
		server.KeyStore = store
	default:
		server.KeyStore = &mem.KeyStore{}
	}

	for name, policy := range config.Policies {
		server.Roles.Set(name, key.NewPolicy(policy.Paths...))
		for _, identity := range policy.Identities {
			if server.Roles.IsAssigned(identity) {
				failf(cli.Output(), "Cannot assign policy '%s' to identity '%s': this identity already has a policy", name, identity)
			}
			server.Roles.Assign(name, identity)
		}
	}

	shutdownContext, shutdownServer := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		_ = <-sigCh
		shutdownServer()
	}()
	if err := server.ServeTCP(shutdownContext, 800*time.Millisecond); err != nil && err != context.Canceled {
		fmt.Fprintln(cli.Output(), err)
	}
}
