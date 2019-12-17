// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/awsecret"
	"github.com/minio/kes/fs"
	"github.com/minio/kes/mem"
	"github.com/minio/kes/vault"
)

const serverCmdUsage = `usage: %s [options]

  --addr               The address of the server (default: 127.0.0.1:7373)
  --config             Path to the server configuration file
  --root               The identity of root - who can perform any operation.
                       A root identity must be specified - either via this 
                       flag or within the config file. This flag takes 
                       precedence over the config file.

  --mlock              Lock all allocated memory pages to prevent the OS from
                       swapping them to the disk and eventually leak secrets.

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

func server(args []string) error {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() {
		fmt.Fprintf(cli.Output(), serverCmdUsage, cli.Name())
	}

	var (
		addr         string
		configPath   string
		rootIdentity string
		mlock        bool

		tlsKeyPath  string
		tlsCertPath string
		mtlsAuth    string
	)
	cli.StringVar(&addr, "addr", "127.0.0.1:7373", "The address of the server")
	cli.StringVar(&configPath, "config", "", "Path to the server configuration file")
	cli.StringVar(&rootIdentity, "root", "", "The identity of root - who can perform any operation")
	cli.BoolVar(&mlock, "mlock", false, "Lock all allocated memory pages")
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
		return fmt.Errorf("Cannot read config file: %v", err)
	}
	if !isFlagPresent(cli, "addr") && config.Addr != "" {
		addr = config.Addr
	}
	if rootIdentity == "" {
		if config.Root == "" {
			return errors.New("No root identity has been specified")
		}
		rootIdentity = config.Root.String()
	}
	if tlsKeyPath == "" {
		if config.TLS.KeyPath == "" {
			return errors.New("No private key file has been specified")
		}
		tlsKeyPath = config.TLS.KeyPath
	}
	if tlsCertPath == "" {
		if config.TLS.CertPath == "" {
			return errors.New("No certificate file has been specified")
		}
		tlsCertPath = config.TLS.CertPath
	}

	switch {
	case config.KeyStore.Fs.Dir != "" && config.KeyStore.Vault.Addr != "":
		return errors.New("Ambiguous configuration: FS and Vault key store are specified at the same time")
	case config.KeyStore.Fs.Dir != "" && config.KeyStore.Aws.SecretsManager.Addr != "":
		return errors.New("Ambiguous configuration: FS and AWS Secrets Manager key store are specified at the same time")
	case config.KeyStore.Vault.Addr != "" && config.KeyStore.Aws.SecretsManager.Addr != "":
		return errors.New("Ambiguous configuration: Vault and AWS Secrets Manager key store are specified at the same time")
	}

	if mlock {
		if runtime.GOOS != "linux" {
			return errors.New("Cannot lock memory: syscall requires a linux system")
		}
		if err := mlockall(); err != nil {
			return fmt.Errorf("Cannot lock memory: %v - See: 'man mlockall'", err)
		}
	}

	var store kes.Store
	switch {
	case config.KeyStore.Fs.Dir != "":
		f, err := os.Stat(config.KeyStore.Fs.Dir)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("Failed to open %s: %v", config.KeyStore.Fs.Dir, err)
		}
		if err == nil && !f.IsDir() {
			return fmt.Errorf("%s is not a directory", config.KeyStore.Fs.Dir)
		}
		if os.IsNotExist(err) {
			if err = os.MkdirAll(config.KeyStore.Fs.Dir, 0700); err != nil {
				return fmt.Errorf("Failed to create directory %s: %v", config.KeyStore.Fs.Dir, err)
			}
		}
		store = &fs.KeyStore{
			Dir:                    config.KeyStore.Fs.Dir,
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
		}
	case config.KeyStore.Vault.Addr != "":
		vaultStore := &vault.KeyStore{
			Addr:     config.KeyStore.Vault.Addr,
			Location: config.KeyStore.Vault.Name,
			AppRole: vault.AppRole{
				ID:     config.KeyStore.Vault.AppRole.ID,
				Secret: config.KeyStore.Vault.AppRole.Secret,
				Retry:  config.KeyStore.Vault.AppRole.Retry,
			},
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
			StatusPingAfter:        config.KeyStore.Vault.Status.Ping,
		}
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			return fmt.Errorf("Failed to connect to Vault: %v", err)
		}
		store = vaultStore
	case config.KeyStore.Aws.SecretsManager.Addr != "":
		awsStore := &awsecret.KeyStore{
			Addr:     config.KeyStore.Aws.SecretsManager.Addr,
			Region:   config.KeyStore.Aws.SecretsManager.Region,
			KmsKeyID: config.KeyStore.Aws.SecretsManager.KmsKeyID,
			Login: awsecret.Credentials{
				AccessKey:    config.KeyStore.Aws.SecretsManager.Login.AccessKey,
				SecretKey:    config.KeyStore.Aws.SecretsManager.Login.SecretKey,
				SessionToken: config.KeyStore.Aws.SecretsManager.Login.SessionToken,
			},
		}
		if err := awsStore.Authenticate(); err != nil {
			return fmt.Errorf("Failed to connect to AWS Secrets Manager: %v", err)
		}
		store = awsStore
	default:
		store = &mem.KeyStore{
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
		}
	}

	roles := &kes.Roles{
		Root: kes.Identity(rootIdentity),
	}
	for name, policy := range config.Policies {
		roles.Set(name, kes.NewPolicy(policy.Paths...))
		for _, identity := range policy.Identities {
			if roles.IsAssigned(identity) {
				return fmt.Errorf("Cannot assign policy '%s' to identity '%s': this identity already has a policy", name, identity)
			}
			roles.Assign(name, identity)
		}
	}

	const maxBody = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", kes.RequireMethod(http.MethodPost, kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleCreateKey(store)))))
	mux.Handle("/v1/key/delete/", kes.RequireMethod(http.MethodDelete, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleDeleteKey(store)))))
	mux.Handle("/v1/key/generate/", kes.RequireMethod(http.MethodPost, kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleGenerateKey(store)))))
	mux.Handle("/v1/key/decrypt/", kes.RequireMethod(http.MethodPost, kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleDecryptKey(store)))))

	mux.Handle("/v1/policy/write/", kes.RequireMethod(http.MethodPost, kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleWritePolicy(roles)))))
	mux.Handle("/v1/policy/read/", kes.RequireMethod(http.MethodGet, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleReadPolicy(roles)))))
	mux.Handle("/v1/policy/list/", kes.RequireMethod(http.MethodGet, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleListPolicies(roles)))))
	mux.Handle("/v1/policy/delete/", kes.RequireMethod(http.MethodDelete, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleDeletePolicy(roles)))))

	mux.Handle("/v1/identity/assign/", kes.RequireMethod(http.MethodPost, kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleAssignIdentity(roles)))))
	mux.Handle("/v1/identity/list/", kes.RequireMethod(http.MethodGet, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleListIdentities(roles)))))
	mux.Handle("/v1/identity/forget/", kes.RequireMethod(http.MethodDelete, kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleForgetIdentity(roles)))))

	server := http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},

		ReadTimeout:       5 * time.Second,
		WriteTimeout:      20 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
	switch mtlsAuth {
	case "verify":
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "ignore":
		server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
	default:
		return fmt.Errorf("Invalid option for --mtls-auth: %s", mtlsAuth)
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
			fmt.Fprintf(cli.Output(), "Abnormal server shutdown: %v\n", err)
		}
	}()
	if err := server.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != http.ErrServerClosed {
		return fmt.Errorf("Cannot start server: %v", err)
	}
	return nil
}
