// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
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
	"sync"
	"syscall"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/aws"
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

	errorLog := kes.NewLogger(os.Stderr, "", log.LstdFlags)
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

	auditLog := kes.NewLogger(ioutil.Discard, "", 0)
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

	roles := &kes.Roles{
		Root: kes.Identity(rootIdentity),
	}
	for name, policy := range config.Policies {
		roles.Set(name, kes.NewPolicy(policy.Paths...))
		for _, identity := range policy.Identities {
			if roles.IsAssigned(identity) {
				return fmt.Errorf("Cannot assign policy '%s' to identity '%s': this identity already has a policy", name, identity)
			}
			if identity != kes.IdentityUnknown {
				roles.Assign(name, identity)
			}
		}
	}

	const maxBody = 1 << 20
	mux := http.NewServeMux()
	mux.Handle("/v1/key/create/", timeout(15*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/key/create/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleCreateKey(store))))))))
	mux.Handle("/v1/key/import/", timeout(15*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/key/import/*", kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleImportKey(store))))))))
	mux.Handle("/v1/key/delete/", timeout(15*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodDelete, kes.ValidatePath("/v1/key/delete/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleDeleteKey(store))))))))
	mux.Handle("/v1/key/generate/", timeout(15*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/key/generate/*", kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleGenerateKey(store))))))))
	mux.Handle("/v1/key/decrypt/", timeout(15*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/key/decrypt/*", kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleDecryptKey(store))))))))

	mux.Handle("/v1/policy/write/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/policy/write/*", kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleWritePolicy(roles))))))))
	mux.Handle("/v1/policy/read/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodGet, kes.ValidatePath("/v1/policy/read/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleReadPolicy(roles))))))))
	mux.Handle("/v1/policy/list/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodGet, kes.ValidatePath("/v1/policy/list/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleListPolicies(roles))))))))
	mux.Handle("/v1/policy/delete/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodDelete, kes.ValidatePath("/v1/policy/delete/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleDeletePolicy(roles))))))))

	mux.Handle("/v1/identity/assign/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodPost, kes.ValidatePath("/v1/identity/assign/*/*", kes.LimitRequestBody(maxBody, kes.EnforcePolicies(roles, kes.HandleAssignIdentity(roles))))))))
	mux.Handle("/v1/identity/list/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodGet, kes.ValidatePath("/v1/identity/list/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleListIdentities(roles))))))))
	mux.Handle("/v1/identity/forget/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodDelete, kes.ValidatePath("/v1/identity/forget/*", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleForgetIdentity(roles))))))))

	mux.Handle("/v1/log/audit/trace", kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodGet, kes.ValidatePath("/v1/log/audit/trace", kes.LimitRequestBody(0, kes.EnforcePolicies(roles, kes.HandleTraceAuditLog(auditLog)))))))

	mux.Handle("/version", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, kes.RequireMethod(http.MethodGet, kes.ValidatePath("/version", kes.LimitRequestBody(0, kes.HandleVersion(version))))))) // /version is accessible to any identity
	mux.Handle("/", timeout(10*time.Second, kes.AuditLog(auditLog.Log(), roles, http.NotFound)))

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

// timeout returns and HTTP handler that runs f
// with the given time limit.
//
// If the time limit exceeds before f has written
// any response to the client, timeout will return
// http.StatusServiceUnavailable (503) to the client.
//
// If the time limit exceeds after f has written
// a response to the client timeout will not write
// any response to the client. However, it will return
// such that the HTTP server eventually closes the
// underlying connection.
// Any further attempt by f to write to the client after
// the timeout limit has been exceeded will fail with
// http.ErrHandlerTimeout.
//
// If f implements a long-running job then it should either
// stop once request.Context().Done() completes or once
// if a responseWriter.Write(...) call returns http.ErrHandlerTimeout.
func timeout(after time.Duration, f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancelCtx := context.WithTimeout(r.Context(), after)
		defer cancelCtx()

		r = r.WithContext(ctx)
		tw := newTimeoutWriter(w)

		done := make(chan struct{})
		panicChan := make(chan interface{}, 1)
		go func() {
			defer func() {
				if p := recover(); p != nil {
					panicChan <- p
				}
			}()
			f(tw, r)
			close(done)
		}()

		select {
		case p := <-panicChan:
			panic(p)
		case <-ctx.Done():
			tw.timeout()
		case <-done:
		}
	}
}

var _ http.ResponseWriter = (*timeoutWriter)(nil)
var _ http.Flusher = (*timeoutWriter)(nil)
var _ http.Pusher = (*timeoutWriter)(nil)

// timeoutWriter is a http.ResponseWriter that implements
// http.Flusher and http.Pusher. It synchronizes a potential
// timeout and the writes by the http.ResponseWriter it wraps.
type timeoutWriter struct {
	writer  http.ResponseWriter
	flusher http.Flusher
	pusher  http.Pusher

	lock       sync.Mutex
	timedOut   bool
	hasWritten bool
}

func newTimeoutWriter(w http.ResponseWriter) *timeoutWriter {
	tw := &timeoutWriter{
		writer: w,
	}
	if flusher, ok := w.(http.Flusher); ok {
		tw.flusher = flusher
	}
	if pusher, ok := w.(http.Pusher); ok {
		tw.pusher = pusher
	}
	return tw
}

// timeout returns http.StatusServiceUnavailable to the client
// if no response has been written to the client, yet.
func (tw *timeoutWriter) timeout() {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	tw.timedOut = true
	if !tw.hasWritten {
		tw.hasWritten = true
		http.Error(tw.writer, "timeout", http.StatusServiceUnavailable)
	}
}

func (tw *timeoutWriter) Header() http.Header { return tw.writer.Header() }

func (tw *timeoutWriter) WriteHeader(statusCode int) {
	tw.lock.Lock()
	defer tw.lock.Unlock()

	if tw.timedOut {
		if !tw.hasWritten {
			tw.hasWritten = true
			http.Error(tw.writer, "timeout", http.StatusServiceUnavailable)
		}
	} else {
		tw.hasWritten = true
		tw.writer.WriteHeader(statusCode)
	}
}

func (tw *timeoutWriter) Write(p []byte) (int, error) {
	// We must not hold the lock while writing to the
	// underlying http.ResponseWriter (via Write([]byte))
	// b/c e.g. a slow/malisious client would block the
	// lock.Unlock.
	// In this case we cannot accquire the lock when we
	// want to mark the timeoutWriter as timed out (See: timeout()).
	// So, the client would block the actual handler by slowly
	// reading the response and the timeout handler since it
	// would not be able to accquire the lock until the Write([]byte)
	// finishes.
	// Therefore, we must release the lock before writing
	// the (eventually large) response body to the client.
	tw.lock.Lock()
	if tw.timedOut {
		tw.lock.Unlock()
		return 0, http.ErrHandlerTimeout
	}
	if !tw.hasWritten {
		tw.hasWritten = true
		tw.writer.WriteHeader(http.StatusOK)
	}
	tw.lock.Unlock()

	return tw.writer.Write(p)
}

func (tw *timeoutWriter) Flush() {
	if tw.flusher != nil {
		tw.flusher.Flush()
	}
}

func (tw *timeoutWriter) Push(target string, opts *http.PushOptions) error {
	if tw.pusher != nil {
		return tw.pusher.Push(target, opts)
	}
	return http.ErrNotSupported
}
