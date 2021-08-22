// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/aws"
	"github.com/minio/kes/internal/fs"
	xhttp "github.com/minio/kes/internal/http"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/secret"
	"github.com/minio/kes/internal/vault"
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

	errorLog := xlog.NewLogger(os.Stderr, "", log.LstdFlags)
	if len(config.Log.Error.Files) > 0 {
		var files []io.Writer
		for _, path := range config.Log.Error.Files {
			if path == "" { // ignore empty entries in the config file
				continue
			}

			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return fmt.Errorf("Failed to open error log file '%s': %v", path, err)
			}
			defer file.Close()
			files = append(files, file)
		}
		if len(files) > 0 { // only create non-default error log if we have files
			errorLog.SetOutput(files...)
		}
	}

	auditLog := xlog.NewLogger(ioutil.Discard, "", 0)
	if len(config.Log.Audit.Files) > 0 {
		var files []io.Writer
		for _, path := range config.Log.Audit.Files {
			if path == "" { // ignore empty entries in the config file
				continue
			}

			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				return fmt.Errorf("Failed to open audit log file '%s': %v", path, err)
			}
			defer file.Close()
			files = append(files, file)
		}
		if len(files) > 0 { // only create non-default audit log if we have files
			auditLog.SetOutput(files...)
		}
	}

	var store secret.Store
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
			ErrorLog:               errorLog.Log(),
		}
	case config.KeyStore.Vault.Addr != "":
		vaultStore := &vault.KeyStore{
			Addr:      config.KeyStore.Vault.Addr,
			Location:  config.KeyStore.Vault.Name,
			Namespace: config.KeyStore.Vault.Namespace,
			AppRole: vault.AppRole{
				ID:     config.KeyStore.Vault.AppRole.ID,
				Secret: config.KeyStore.Vault.AppRole.Secret,
				Retry:  config.KeyStore.Vault.AppRole.Retry,
			},
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
			StatusPingAfter:        config.KeyStore.Vault.Status.Ping,
			ErrorLog:               errorLog.Log(),
			ClientKeyPath:          config.KeyStore.Vault.TLS.KeyPath,
			ClientCertPath:         config.KeyStore.Vault.TLS.CertPath,
			CAPath:                 config.KeyStore.Vault.TLS.CAPath,
		}
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			return fmt.Errorf("Failed to connect to Vault: %v", err)
		}
		store = vaultStore
	case config.KeyStore.Aws.SecretsManager.Addr != "":
		awsStore := &aws.SecretsManager{
			Addr:                   config.KeyStore.Aws.SecretsManager.Addr,
			Region:                 config.KeyStore.Aws.SecretsManager.Region,
			KmsKeyID:               config.KeyStore.Aws.SecretsManager.KmsKeyID,
			CacheExpireAfter:       config.Cache.Expiry.All,
			CacheExpireUnusedAfter: config.Cache.Expiry.Unused,
			ErrorLog:               errorLog.Log(),
			Login: aws.Credentials{
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
			ErrorLog:               errorLog.Log(),
		}
	}

	var proxy *auth.TLSProxy
	if len(config.TLS.Proxy.Identities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.Proxy.Header.ClientCert),
		}
		if mtlsAuth == "verify" {
			proxy.VerifyOptions = new(x509.VerifyOptions)
		}
		for _, identity := range config.TLS.Proxy.Identities {
			if identity == kes.Identity(rootIdentity) {
				return fmt.Errorf("Cannot use root identity '%s' as TLS proxy", identity)
			}
			if !identity.IsUnknown() {
				proxy.Add(identity)
			}
		}
	}

	roles := &auth.Roles{
		Root: kes.Identity(rootIdentity),
	}
	for name, policy := range config.Policies {
		p, err := kes.NewPolicy(policy.Paths...)
		if err != nil {
			return fmt.Errorf("Policy '%s' contains invalid path: %v", name, err)
		}
		roles.Set(name, p)

		for _, identity := range policy.Identities {
			if identity == kes.Identity(rootIdentity) {
				return fmt.Errorf("Cannot assign policy '%s' to root identity '%s'", name, identity)
			}
			if proxy != nil && proxy.Is(identity) {
				return fmt.Errorf("Cannot assign policy '%s' to TLS proxy '%s'", name, identity)
			}
			if roles.IsAssigned(identity) {
				return fmt.Errorf("Cannot assign policy '%s' to identity '%s': this identity already has a policy", name, identity)
			}
			if !identity.IsUnknown() {
				roles.Assign(name, identity)
			}
		}
	}

	const maxBody = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", xhttp.Timeout(15*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/create/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleCreateKey(store)))))))))
	mux.Handle("/v1/key/import/", xhttp.Timeout(15*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/import/*", xhttp.LimitRequestBody(maxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleImportKey(store)))))))))
	mux.Handle("/v1/key/delete/", xhttp.Timeout(15*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/key/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeleteKey(store)))))))))
	mux.Handle("/v1/key/generate/", xhttp.Timeout(15*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/generate/*", xhttp.LimitRequestBody(maxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleGenerateKey(store)))))))))
	mux.Handle("/v1/key/decrypt/", xhttp.Timeout(15*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/decrypt/*", xhttp.LimitRequestBody(maxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDecryptKey(store)))))))))

	mux.Handle("/v1/policy/write/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/policy/write/*", xhttp.LimitRequestBody(maxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleWritePolicy(roles)))))))))
	mux.Handle("/v1/policy/read/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/read/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleReadPolicy(roles)))))))))
	mux.Handle("/v1/policy/list/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListPolicies(roles)))))))))
	mux.Handle("/v1/policy/delete/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/policy/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeletePolicy(roles)))))))))

	mux.Handle("/v1/identity/assign/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/identity/assign/*/*", xhttp.LimitRequestBody(maxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleAssignIdentity(roles)))))))))
	mux.Handle("/v1/identity/list/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/identity/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListIdentities(roles)))))))))
	mux.Handle("/v1/identity/forget/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/identity/forget/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleForgetIdentity(roles)))))))))

	mux.Handle("/v1/log/audit/trace", xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/log/audit/trace", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleTraceAuditLog(auditLog))))))))

	mux.Handle("/version", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/version", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.HandleVersion(version)))))))) // /version is accessible to any identity
	mux.Handle("/", xhttp.Timeout(10*time.Second, xhttp.AuditLog(auditLog.Log(), roles, xhttp.TLSProxy(proxy, http.NotFound))))

	server := http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
		ErrorLog: errorLog.Log(),

		ReadTimeout:  5 * time.Second,
		WriteTimeout: 0 * time.Second, // explicitly set no write timeout - see timeout handler.
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
