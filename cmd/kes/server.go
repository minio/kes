// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/aws"
	"github.com/minio/kes/internal/fs"
	"github.com/minio/kes/internal/gcp"
	"github.com/minio/kes/internal/gemalto"
	xhttp "github.com/minio/kes/internal/http"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/secret"
	"github.com/minio/kes/internal/vault"
	"golang.org/x/crypto/ssh/terminal"
)

const serverCmdUsage = `Usage:
    kes server [options]

Options:
    --addr <IP:PORT>       The address of the server (default: 127.0.0.1:7373)
    --config <PATH>        Path to the server configuration file
    --root  <IDENTITY>     The identity of root - who can perform any operation.
                           A root identity must be specified - either via this
                           flag or within the config file. This flag takes
                           precedence over the config file

    --mlock                Lock all allocated memory pages to prevent the OS from
                           swapping them to the disk and eventually leak secrets

    --key <PATH>           Path to the TLS private key. It takes precedence over
                           the config file
    --cert <PATH>          Path to the TLS certificate. It takes precedence over
                           the config file

    --auth {on|off}        Controls how the server handles mTLS authentication.
                           By default, the server requires a client certificate
                           and verifies that certificate has been issued by a
                           trusted CA.
                           Valid options are:
                              Require and verify      : --auth=on (default)
                              Require but don't verify: --auth=off

    -q, --quiet            Do not print information on startup
    -h, --help             Show list of command-line options

Starts a KES server. The server address can be specified in the config file but
may be overwriten by the --addr flag. If omitted the IP defaults to 0.0.0.0 and
the PORT to 7373.

The server's root identity can be specified in the config file but may be overwriten
by the --root flag. The IDENTITY should be a hash of a TLS public key encoded as hex
string. If the IDENTITY is not a public key hash e.g. --root="not-a-hash", the root
identity is effectively disabled.

The client TLS verification can be disabled by setting --auth=off. The server then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ export KES_ROOT_IDENTITY=$(kes tool identity of root.cert)
    $ kes server --key=private.key --cert=public.crt --root="$KES_ROOT_IDENTITY" --auth=off
`

func server(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addr         string
		configPath   string
		rootIdentity string
		mlock        bool
		tlsKeyPath   string
		tlsCertPath  string
		mtlsAuth     string
		quiet        quiet
	)
	cli.StringVar(&addr, "addr", "127.0.0.1:7373", "The address of the server")
	cli.StringVar(&configPath, "config", "", "Path to the server configuration file")
	cli.StringVar(&rootIdentity, "root", "", "The identity of root - who can perform any operation")
	cli.BoolVar(&mlock, "mlock", false, "Lock all allocated memory pages")
	cli.StringVar(&tlsKeyPath, "key", "", "Path to the TLS private key")
	cli.StringVar(&tlsCertPath, "cert", "", "Path to the TLS certificate")
	cli.StringVar(&mtlsAuth, "auth", "on", "Controls how the server handles mTLS authentication")
	cli.Var(&quiet, "q", "Do not print information on startup")
	cli.Var(&quiet, "quiet", "Do not print information on startup")
	cli.Parse(args[1:])

	if cli.NArg() > 0 {
		stdlog.Fatal("Error: too many arguments")
	}

	config, err := loadServerConfig(configPath)
	if err != nil {
		stdlog.Fatalf("Error: failed to read config file: %v", err)
	}
	config.SetDefaults()

	if !isFlagPresent(cli, "addr") && config.Addr != "" {
		addr = config.Addr
	}
	if rootIdentity == "" {
		if config.Root == "" {
			stdlog.Fatal("Error: no root identity has been specified")
		}
		rootIdentity = config.Root.String()
	}
	if tlsKeyPath == "" {
		if config.TLS.KeyPath == "" {
			stdlog.Fatal("Error: no private key file has been specified")
		}
		tlsKeyPath = config.TLS.KeyPath
	}
	if tlsCertPath == "" {
		if config.TLS.CertPath == "" {
			stdlog.Fatal("Error: no certificate file has been specified")
		}
		tlsCertPath = config.TLS.CertPath
	}

	switch {
	case config.Keys.Fs.Path != "" && config.Keys.Vault.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: FS and Hashicorp Vault endpoint specified at the same time")
	case config.Keys.Fs.Path != "" && config.Keys.Aws.SecretsManager.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: FS and AWS Secrets Manager endpoint are specified at the same time")
	case config.Keys.Fs.Path != "" && config.Keys.Gemalto.KeySecure.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: FS and Gemalto KeySecure endpoint are specified at the same time")
	case config.Keys.Fs.Path != "" && config.Keys.GCP.SecretManager.ProjectID != "":
		stdlog.Fatal("Error: ambiguous configuration: FS and GCP secret manager are specified at the same time")
	case config.Keys.Vault.Endpoint != "" && config.Keys.Aws.SecretsManager.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: Hashicorp Vault and AWS SecretsManager endpoint are specified at the same time")
	case config.Keys.Vault.Endpoint != "" && config.Keys.Gemalto.KeySecure.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: Hashicorp Vault and Gemalto KeySecure endpoint are specified at the same time")
	case config.Keys.Vault.Endpoint != "" && config.Keys.GCP.SecretManager.ProjectID != "":
		stdlog.Fatal("Error: ambiguous configuration: Hashicorp Vault and GCP secret manager are specified at the same time")
	case config.Keys.Aws.SecretsManager.Endpoint != "" && config.Keys.Gemalto.KeySecure.Endpoint != "":
		stdlog.Fatal("Error: ambiguous configuration: AWS SecretsManager and Gemalto KeySecure endpoint are specified at the same time")
	case config.Keys.Aws.SecretsManager.Endpoint != "" && config.Keys.GCP.SecretManager.ProjectID != "":
		stdlog.Fatal("Error: ambiguous configuration: AWS SecretsManager and GCP secret manager are specified at the same time")
	case config.Keys.Gemalto.KeySecure.Endpoint != "" && config.Keys.GCP.SecretManager.ProjectID != "":
		stdlog.Fatal("Error: ambiguous configuration: Gemalto KeySecure endpoint and GCP secret manager are specified at the same time")
	}

	if mlock {
		if runtime.GOOS != "linux" {
			stdlog.Fatal("Error: cannot lock memory: syscall requires a linux system")
		}
		if err := mlockall(); err != nil {
			stdlog.Fatalf("Error: failed to lock memory: %v - See: 'man mlockall'", err)
		}
	}

	var errorLog *xlog.SystemLog
	switch strings.ToLower(config.Log.Error) {
	case "on":
		if isTerm(os.Stderr) { // If STDERR is a tty - write plain logs, not JSON.
			errorLog = xlog.NewLogger(os.Stderr, "", stdlog.LstdFlags)
		} else {
			errorLog = xlog.NewLogger(xlog.NewJSONWriter(os.Stderr), "", stdlog.LstdFlags)
		}
	case "off":
		errorLog = xlog.NewLogger(ioutil.Discard, "", stdlog.LstdFlags)
	default:
		stdlog.Fatalf("Error: %q is an invalid error log configuration", config.Log.Error)
	}

	var auditLog *xlog.SystemLog
	switch strings.ToLower(config.Log.Audit) {
	case "on":
		auditLog = xlog.NewLogger(os.Stdout, "", 0)
	case "off":
		auditLog = xlog.NewLogger(ioutil.Discard, "", 0)
	default:
		stdlog.Fatalf("Error: %q is an invalid audit log configuration", config.Log.Audit)
	}

	var proxy *auth.TLSProxy
	if len(config.TLS.Proxy.Identities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.Proxy.Header.ClientCert),
		}
		if strings.ToLower(mtlsAuth) != "off" {
			proxy.VerifyOptions = new(x509.VerifyOptions)
		}
		for _, identity := range config.TLS.Proxy.Identities {
			if identity == kes.Identity(rootIdentity) {
				stdlog.Fatalf("Error: cannot use root identity %q as TLS proxy", identity)
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
			stdlog.Fatalf("Error: policy %q contains invalid glob patterns: %v", name, err)
		}
		roles.Set(name, p)

		for _, identity := range policy.Identities {
			if identity == kes.Identity(rootIdentity) {
				stdlog.Fatalf("Error: cannot assign policy %q to root identity %q", name, identity)
			}
			if proxy != nil && proxy.Is(identity) {
				stdlog.Fatalf("Error: cannot assign policy %q to TLS proxy %q", name, identity)
			}
			if roles.IsAssigned(identity) {
				stdlog.Fatalf("Error: cannot assign policy %q to identity %q: this identity already has a policy", name, identity)
			}
			if !identity.IsUnknown() {
				roles.Assign(name, identity)
			}
		}
	}

	var (
		store            = &secret.Store{}
		keyStore         string
		keyStoreEndpoint string
	)
	switch {
	case config.Keys.Fs.Path != "":
		f, err := os.Stat(config.Keys.Fs.Path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			stdlog.Fatalf("Error: failed to open %q: %v", config.Keys.Fs.Path, err)
		}
		if err == nil && !f.IsDir() {
			stdlog.Fatalf("Error: %q is not a directory", config.Keys.Fs.Path)
		}
		if errors.Is(err, os.ErrNotExist) {
			msg := fmt.Sprintf("Creating directory '%s' ... ", config.Keys.Fs.Path)
			quiet.Print(msg)
			if err = os.MkdirAll(config.Keys.Fs.Path, 0700); err != nil {
				stdlog.Fatalf("Error: failed to create directory %q: %v", config.Keys.Fs.Path, err)
			}
			quiet.ClearMessage(msg)
		}
		store.Remote = &fs.Store{
			Dir:      config.Keys.Fs.Path,
			ErrorLog: errorLog.Log(),
		}

		keyStore = "Filesystem"
		if keyStoreEndpoint, err = filepath.Abs(config.Keys.Fs.Path); err != nil {
			keyStoreEndpoint = config.Keys.Fs.Path
		}
	case config.Keys.Vault.Endpoint != "":
		vaultStore := &vault.Store{
			Addr:      config.Keys.Vault.Endpoint,
			Engine:    config.Keys.Vault.EnginePath,
			Location:  config.Keys.Vault.Prefix,
			Namespace: config.Keys.Vault.Namespace,
			AppRole: vault.AppRole{
				Engine: config.Keys.Vault.AppRole.EnginePath,
				ID:     config.Keys.Vault.AppRole.ID,
				Secret: config.Keys.Vault.AppRole.Secret,
				Retry:  config.Keys.Vault.AppRole.Retry,
			},
			StatusPingAfter: config.Keys.Vault.Status.Ping,
			ErrorLog:        errorLog.Log(),
			ClientKeyPath:   config.Keys.Vault.TLS.KeyPath,
			ClientCertPath:  config.Keys.Vault.TLS.CertPath,
			CAPath:          config.Keys.Vault.TLS.CAPath,
		}

		msg := fmt.Sprintf("Authenticating to Hashicorp Vault '%s' ... ", vaultStore.Addr)
		quiet.Print(msg)
		if err := vaultStore.Authenticate(context.Background()); err != nil {
			stdlog.Fatalf("Error: failed to connect to Vault: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = vaultStore

		keyStore = "Hashicorp Vault"
		keyStoreEndpoint = config.Keys.Vault.Endpoint
	case config.Keys.Aws.SecretsManager.Endpoint != "":
		awsStore := &aws.SecretsManager{
			Addr:     config.Keys.Aws.SecretsManager.Endpoint,
			Region:   config.Keys.Aws.SecretsManager.Region,
			KMSKeyID: config.Keys.Aws.SecretsManager.KmsKey,
			ErrorLog: errorLog.Log(),
			Login: aws.Credentials{
				AccessKey:    config.Keys.Aws.SecretsManager.Login.AccessKey,
				SecretKey:    config.Keys.Aws.SecretsManager.Login.SecretKey,
				SessionToken: config.Keys.Aws.SecretsManager.Login.SessionToken,
			},
		}

		msg := fmt.Sprintf("Authenticating to AWS SecretsManager '%s' ... ", awsStore.Addr)
		quiet.Print(msg)
		if err := awsStore.Authenticate(); err != nil {
			stdlog.Fatalf("Error: failed to connect to AWS Secrets Manager: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = awsStore

		keyStore = "AWS SecretsManager"
		keyStoreEndpoint = config.Keys.Aws.SecretsManager.Endpoint
	case config.Keys.Gemalto.KeySecure.Endpoint != "":
		gemaltoStore := &gemalto.KeySecure{
			Endpoint: config.Keys.Gemalto.KeySecure.Endpoint,
			CAPath:   config.Keys.Gemalto.KeySecure.TLS.CAPath,
			ErrorLog: errorLog.Log(),
			Login: gemalto.Credentials{
				Token:  config.Keys.Gemalto.KeySecure.Login.Token,
				Domain: config.Keys.Gemalto.KeySecure.Login.Domain,
				Retry:  config.Keys.Gemalto.KeySecure.Login.Retry,
			},
		}

		msg := fmt.Sprintf("Authenticating to Gemalto KeySecure '%s' ... ", gemaltoStore.Endpoint)
		quiet.Printf(msg)
		if err := gemaltoStore.Authenticate(); err != nil {
			stdlog.Fatalf("Error: failed to connect to Gemalto KeySecure: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = gemaltoStore

		keyStore = "Gemalto KeySecure"
		keyStoreEndpoint = config.Keys.Gemalto.KeySecure.Endpoint
	case config.Keys.GCP.SecretManager.ProjectID != "":
		gcpStore := &gcp.SecretManager{
			Endpoint:  config.Keys.GCP.SecretManager.Endpoint,
			ProjectID: config.Keys.GCP.SecretManager.ProjectID,
			ErrorLog:  errorLog.Log(),
		}

		msg := fmt.Sprintf("Authenticating to GCP SecretManager Project: '%s' ... ", gcpStore.ProjectID)
		quiet.Printf(msg)
		err := gcpStore.Authenticate(gcp.Credentials{
			ClientID: config.Keys.GCP.SecretManager.Credentials.ClientID,
			Client:   config.Keys.GCP.SecretManager.Credentials.Client,
			KeyID:    config.Keys.GCP.SecretManager.Credentials.KeyID,
			Key:      config.Keys.GCP.SecretManager.Credentials.Key,
		})
		if err != nil {
			stdlog.Fatalf("Error: failed to connect to GCP SecretManager: %v", err)
		}
		quiet.ClearMessage(msg)
		store.Remote = gcpStore

		keyStore = "GCP SecretManager"
		keyStoreEndpoint = config.Keys.GCP.SecretManager.Endpoint + " | Project: " + config.Keys.GCP.SecretManager.ProjectID
	default:
		store.Remote = &mem.Store{}

		keyStore = "In-Memory"
		keyStoreEndpoint = "non-persistent"
	}
	store.StartGC(context.Background(), config.Cache.Expiry.Any, config.Cache.Expiry.Unused)

	const MaxBody = 1 << 20 // 1 MiB
	metrics := metric.New()
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/create/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleCreateKey(store))))))))))))
	mux.Handle("/v1/key/import/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/import/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleImportKey(store))))))))))))
	mux.Handle("/v1/key/delete/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/key/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeleteKey(store))))))))))))
	mux.Handle("/v1/key/generate/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/generate/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleGenerateKey(store))))))))))))
	mux.Handle("/v1/key/encrypt/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/encrypt/*", xhttp.LimitRequestBody(MaxBody/2, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleEncryptKey(store))))))))))))
	mux.Handle("/v1/key/decrypt/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/decrypt/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDecryptKey(store))))))))))))
	mux.Handle("/v1/key/list/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/key/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListKeys(store))))))))))))

	mux.Handle("/v1/policy/write/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/policy/write/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleWritePolicy(roles))))))))))))
	mux.Handle("/v1/policy/read/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/read/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleReadPolicy(roles))))))))))))
	mux.Handle("/v1/policy/list/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListPolicies(roles))))))))))))
	mux.Handle("/v1/policy/delete/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/policy/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeletePolicy(roles))))))))))))

	mux.Handle("/v1/identity/assign/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/identity/assign/*/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleAssignIdentity(roles))))))))))))
	mux.Handle("/v1/identity/list/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/identity/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListIdentities(roles))))))))))))
	mux.Handle("/v1/identity/forget/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/identity/forget/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleForgetIdentity(roles))))))))))))

	mux.Handle("/v1/log/audit/trace", metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/log/audit/trace", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleTraceAuditLog(auditLog)))))))))))
	mux.Handle("/v1/log/error/trace", metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/log/error/trace", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleTraceErrorLog(errorLog)))))))))))

	mux.Handle("/v1/metrics", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/metrics", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleMetrics(metrics))))))))))))

	mux.Handle("/version", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.EnforceHTTP2(xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/version", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.HandleVersion(version))))))))))) // /version is accessible to any identity
	mux.Handle("/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.EnforceHTTP2(xhttp.AuditLog(auditLog.Log(), roles, xhttp.TLSProxy(proxy, http.NotFound)))))))

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
	switch strings.ToLower(mtlsAuth) {
	case "on":
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "off":
		server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
	default:
		stdlog.Fatalf("Error: invalid option for --auth: %q", mtlsAuth)
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
			stdlog.Fatalf("Error: abnormal server shutdown: %v", err)
		}
	}()

	// The following code prints a server startup message similar to:
	//
	// Endpoint: https://127.0.0.1:7373        https://192.168.161.34:7373
	//           https://189.27.2.1:7373
	//
	// Root:     3ecfcdf38fcbe141ae26a1030f81e96b753365a46760ae6b578698a97c59fd22
	// Auth:     on    [ only clients with trusted certificates can connect ]
	//
	// Keys:     Filesystem: /tmp/keys
	//
	// CLI:      export KES_SERVER=https://127.0.0.1:7373
	//           export KES_CLIENT_KEY=<client-private-key>   // e.g. $HOME/root.key
	//           export KES_CLIENT_CERT=<client-certificate>  // e.g. $HOME/root.cert
	//           kes --help
	//
	// -----------------------------------------
	// We don't need to worry about non-terminal / windows terminals b/c
	// the color package only prints terminal color sequences if the
	// terminal supports colorized output (see: color.NoColor).
	//
	// If quiet is set to true, all quiet.Print* statements become no-ops.
	var (
		blue   = color.New(color.FgBlue)
		bold   = color.New(color.Bold)
		italic = color.New(color.Italic)
	)
	ip, port := serverAddr(addr)

	const margin = 10 // len("Endpoint: ")
	quiet.Print(blue.Sprint("Endpoint: "))
	quiet.Println(bold.Sprint(alignEndpoints(margin, interfaceIP4Addrs(), port)))
	quiet.Println()

	if r, err := hex.DecodeString(rootIdentity); err == nil && len(r) == sha256.Size {
		quiet.Println(blue.Sprint("Root:    "), rootIdentity)
	} else {
		quiet.Println(blue.Sprint("Root:    "), "_     [ disabled ]")
	}
	if auth := strings.ToLower(mtlsAuth); auth == "on" {
		quiet.Println(blue.Sprint("Auth:    "), color.New(color.Bold, color.FgGreen).Sprint("on "), color.GreenString("  [ only clients with trusted certificates can connect ]"))
	} else {
		quiet.Println(blue.Sprint("Auth:    "), color.New(color.Bold, color.FgYellow).Sprint("off"), color.YellowString("  [ any client can connect but policies still apply ]"))
	}
	quiet.Println()

	quiet.Println(blue.Sprint("Keys:    "), fmt.Sprintf("%s: %s", keyStore, keyStoreEndpoint))
	quiet.Println()

	if runtime.GOOS == "windows" {
		quiet.Println(blue.Sprint("CLI:     "), bold.Sprintf("set KES_SERVER=https://%v:%s", ip, port))
		quiet.Println("         ", bold.Sprint("set KES_CLIENT_KEY=")+italic.Sprint("<client-private-key>")+`   // e.g. root.key`)
		quiet.Println("         ", bold.Sprint("set KES_CLIENT_CERT=")+italic.Sprint("<client-certificate>")+`  // e.g. root.cert`)
		quiet.Println("         ", bold.Sprint("kes --help"))
	} else {
		quiet.Println(blue.Sprint("CLI:     "), bold.Sprintf("export KES_SERVER=https://%v:%s", ip, port))
		quiet.Println("         ", bold.Sprint("export KES_CLIENT_KEY=")+italic.Sprint("<client-private-key>")+"   // e.g. $HOME/root.key")
		quiet.Println("         ", bold.Sprint("export KES_CLIENT_CERT=")+italic.Sprint("<client-certificate>")+"  // e.g. $HOME/root.cert")
		quiet.Println("         ", bold.Sprint("kes --help"))
	}

	// Start the HTTPS server
	if err := server.ListenAndServeTLS(tlsCertPath, tlsKeyPath); err != http.ErrServerClosed {
		stdlog.Fatalf("Error: failed to start server: %v", err)
	}
}

// quiet is a boolean flag.Value that can print
// to STDOUT.
//
// If quiet is set to true then all quiet.Print*
// calls become no-ops and no output is printed to
// STDOUT.
type quiet bool

var _ flag.Getter = (*quiet)(nil) // compiler check

// IsBoolFlag returns true indicating that quiet is a
// boolean flag.
//
// Implemented to satisfy a private interface of the
// flag package.
func (*quiet) IsBoolFlag() bool { return true }

// Set sets the flag's value to s. The string s
// may be "true"/"on" or "flase"/"off".
func (q *quiet) Set(s string) error {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "on", "":
		*q = true
	case "false", "off":
		*q = false
	default:
		return errors.New("parse error") // Same as flag.errParse
	}
	return nil
}

// String retruns the string representation of quiet.
// It returns either "true" or "false".
func (q *quiet) String() string {
	if *q {
		return "true"
	}
	return "false"
}

// Get returns the value of quiet as boolean.
func (q *quiet) Get() interface{} { return bool(*q) }

// Print behaves as fmt.Print if quiet is false.
// Otherwise, Print does nothing.
func (q quiet) Print(a ...interface{}) {
	if !q {
		fmt.Print(a...)
	}
}

// Printf behaves as fmt.Printf if quiet is false.
// Otherwise, Printf does nothing.
func (q quiet) Printf(format string, a ...interface{}) {
	if !q {
		fmt.Printf(format, a...)
	}
}

// Println behaves as fmt.Println if quiet is false.
// Otherwise, Println does nothing.
func (q quiet) Println(a ...interface{}) {
	if !q {
		fmt.Println(a...)
	}
}

// ClearMessage tries to erase the given message from STDOUT
// if STDOUT is a terminal that supports terminal control sequences.
//
// Otherwise, ClearMessage just prints an empty newline.
func (q quiet) ClearMessage(msg string) {
	if color.NoColor {
		q.Println()
		return
	}

	const (
		eraseLine = "\033[2K\r"
		moveUp    = "\033[1A"
	)
	width, _, err := terminal.GetSize(int(os.Stdout.Fd()))
	if err != nil { // If we cannot get the width, just erasure one line
		q.Print(eraseLine)
		return
	}

	// Erase and move up one line as long as the message is not empty.
	for len(msg) > 0 {
		q.Print(eraseLine)

		if len(msg) < width {
			break
		}
		q.Print(moveUp)
		msg = msg[width:]
	}
}

// alignEndpoints turns the given IPs into endpoints of the form
// https://<ip>:<port> and returns a string representation of all
// endpoints.
//
// The returned string has two endpoints per line and after every new
// line leftMargin whitespaces are added to algin each line properly.
//
// alginEndpoints returns a string like:
//  https://<ip-1>:<port>   https://<ip-2>:<port>
//  <margin> https://<ip-3>:<port>   https://<ip-4>:<port>
//  <margin> https://<ip-6>:<port>   https://<ip-5>:<port>
//  ...
func alignEndpoints(leftMargin int, IPs []net.IP, port string) string {
	const maxEndpointSize = 28 // len("https://255.255.255.255:7373")

	var (
		endpoints string
		n         int
	)
	for _, ip := range IPs {
		endpoint := fmt.Sprintf("https://%v:%s", ip, port)
		endpoint += strings.Repeat(" ", 2+maxEndpointSize-len(endpoint)) // pad with white spaces
		if n == 2 {
			endpoints += "\n" + strings.Repeat(" ", leftMargin)
			n = 0
		}
		endpoints += endpoint
		n++
	}
	return endpoints
}

// interfaceIP4Addrs returns a list of the system's unicast
// IPv4 interface addresses.
func interfaceIP4Addrs() []net.IP {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return []net.IP{}
	}

	var ip4Addr []net.IP
	for _, iface := range interfaces {
		var ip net.IP
		switch addr := iface.(type) {
		case *net.IPNet:
			ip = addr.IP.To4()
		case *net.IPAddr:
			ip = addr.IP.To4()
		}
		if ip != nil {
			ip4Addr = append(ip4Addr, ip)
		}
	}
	return ip4Addr
}

// serverAddr takes an address string <IP>:<port> and
// splits it into an IP address and port number.
//
// If addr does not contain an IP (":<port>") then ip will be
// 0.0.0.0.
func serverAddr(addr string) (ip net.IP, port string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		stdlog.Fatalf("Error: invalid server address: %q", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}

	ip = net.ParseIP(host)
	if ip == nil {
		stdlog.Fatalf("Error: invalid server address: %q", addr)
	}
	if ip.IsUnspecified() {
		ip = net.IPv4(127, 0, 0, 1)
	}
	return ip, port
}
