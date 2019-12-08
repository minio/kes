// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	key "github.com/minio/keys"
	"github.com/minio/keys/fs"
	"github.com/minio/keys/mem"
	"github.com/minio/keys/vault"
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

  --mtls-auth          Controls how the server handles client certificates.
                       Valid options are:
                          Require and verify      : --mtls-auth=verify (default)
                          Require but don't verify: --mtls-auth=ignore
                       By default, the server will verify that the certificate
                       presented by the client during the TLS handshake has been
                       signed by a trusted CA.
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
		mtlsAuth    string
	)
	cli.StringVar(&addr, "addr", "127.0.0.1:7373", "The address of the server")
	cli.StringVar(&configPath, "config", "", "Path to the server configuration file")
	cli.StringVar(&rootIdentity, "root", "", "The identity of root - who can perform any operation")
	cli.StringVar(&tlsKeyPath, "tls-key", "", "Path to the TLS private key")
	cli.StringVar(&tlsCertPath, "tls-cert", "", "Path to the TLS certificate")
	cli.StringVar(&mtlsAuth, "mtls-auth", "verify", "Controls how the server handles client certificates.")
	cli.Parse(args[1:])
	if cli.NArg() != 0 {
		cli.Usage()
		os.Exit(2)
	}

	config, err := loadServerConfig(configPath)
	if err != nil {
		failf(cli.Output(), "Cannot read config file: %v", err)
	}
	if !isFlagPresent(cli, "addr") && config.Addr != "" {
		addr = config.Addr
	}
	if rootIdentity == "" {
		if config.Root == "" {
			failf(cli.Output(), "No root identity has been specified")
		}
		rootIdentity = config.Root.String()
	}
	if tlsKeyPath == "" {
		if config.TLS.KeyPath == "" {
			failf(cli.Output(), "No private key file has been specified")
		}
		tlsKeyPath = config.TLS.KeyPath
	}
	if tlsCertPath == "" {
		if config.TLS.CertPath == "" {
			failf(cli.Output(), "No certificate file has been specified")
		}
		tlsCertPath = config.TLS.CertPath
	}

	if config.Fs.Dir != "" && config.Vault.Addr != "" {
		failf(cli.Output(), "Ambiguous configuration: more than one key store specified")
	}

	var store key.Store
	switch {
	case config.Fs.Dir != "":
		f, err := os.Stat(config.Fs.Dir)
		if err != nil && !os.IsNotExist(err) {
			failf(cli.Output(), "Failed to open %s: %v", config.Fs.Dir, err)
		}
		if err == nil && !f.IsDir() {
			failf(cli.Output(), "%s is not a directory", config.Fs.Dir)
		}
		if os.IsNotExist(err) {
			if err = os.MkdirAll(config.Fs.Dir, 0700); err != nil {
				failf(cli.Output(), "Failed to create directory %s: %v", config.Fs.Dir, err)
			}
		}
		store = &fs.KeyStore{
			Dir:                    config.Fs.Dir,
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
		}
	case config.Vault.Addr != "":
		vaultStore := &vault.KeyStore{
			Addr:     config.Vault.Addr,
			Location: config.Vault.Name,
			AppRole: vault.AppRole{
				ID:     config.Vault.AppRole.ID,
				Secret: config.Vault.AppRole.Secret,
				Retry:  config.Vault.AppRole.Retry,
			},
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
			StatusPingAfter:        config.Vault.Status.Ping,
		}
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			failf(cli.Output(), "Failed to connect to Vault: %v", err)
		}
		store = vaultStore
	default:
		store = &mem.KeyStore{
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
		}
	}

	roles := &key.Roles{
		Root: key.Identity(rootIdentity),
	}
	for name, policy := range config.Policies {
		roles.Set(name, key.NewPolicy(policy.Paths...))
		for _, identity := range policy.Identities {
			if roles.IsAssigned(identity) {
				failf(cli.Output(), "Cannot assign policy '%s' to identity '%s': this identity already has a policy", name, identity)
			}
			roles.Assign(name, identity)
		}
	}

	const maxBody = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", key.RequireMethod(http.MethodPost, key.LimitRequestBody(maxBody, key.EnforcePolicies(roles, key.HandleCreateKey(store)))))
	mux.Handle("/v1/key/delete/", key.RequireMethod(http.MethodDelete, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleDeleteKey(store)))))
	mux.Handle("/v1/key/generate/", key.RequireMethod(http.MethodPost, key.LimitRequestBody(maxBody, key.EnforcePolicies(roles, key.HandleGenerateKey(store)))))
	mux.Handle("/v1/key/decrypt/", key.RequireMethod(http.MethodPost, key.LimitRequestBody(maxBody, key.EnforcePolicies(roles, key.HandleDecryptKey(store)))))

	mux.Handle("/v1/policy/write/", key.RequireMethod(http.MethodPost, key.LimitRequestBody(maxBody, key.EnforcePolicies(roles, key.HandleWritePolicy(roles)))))
	mux.Handle("/v1/policy/read/", key.RequireMethod(http.MethodGet, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleReadPolicy(roles)))))
	mux.Handle("/v1/policy/list/", key.RequireMethod(http.MethodGet, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleListPolicies(roles)))))
	mux.Handle("/v1/policy/delete/", key.RequireMethod(http.MethodDelete, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleDeletePolicy(roles)))))

	mux.Handle("/v1/identity/assign/", key.RequireMethod(http.MethodPost, key.LimitRequestBody(maxBody, key.EnforcePolicies(roles, key.HandleAssignIdentity(roles)))))
	mux.Handle("/v1/identity/list/", key.RequireMethod(http.MethodGet, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleListIdentities(roles)))))
	mux.Handle("/v1/identity/forget/", key.RequireMethod(http.MethodDelete, key.LimitRequestBody(0, key.EnforcePolicies(roles, key.HandleForgetIdentity(roles)))))

	server := http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}
	switch mtlsAuth {
	case "verify":
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "ignore":
		server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
	default:
		failf(cli.Output(), "Invalid option for --mtls-auth: %s", mtlsAuth)
	}

	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh

		shutdownContext, cancelShutdown := context.WithDeadline(context.Background(), time.Now().Add(800*time.Millisecond))
		err := server.Shutdown(shutdownContext)
		if cancelShutdown(); err == context.DeadlineExceeded {
			err = server.Close()
		}
		if err != nil {
			failf(cli.Output(), "Abnormal server shutdown: %v", err)
		}
	}()
	if err := server.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != http.ErrServerClosed {
		failf(cli.Output(), "Cannot start server: %v", err)
	}
}
