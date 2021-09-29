// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/fips"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/secure-io/sio-go/sioutil"
)

const gatewayCmdUsage = `Usage:
    kes gateway [options]

Options:
    --addr <IP:PORT>       The address of the gateway (default: 0.0.0.0:7373)
    --config <PATH>        Path to the gateway configuration file
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

    --auth {on|off}        Controls how the gateway handles mTLS authentication.
                           By default, the gateway requires a client certificate
                           and verifies that certificate has been issued by a
                           trusted CA.
                           Valid options are:
                              Require and verify      : --auth=on (default)
                              Require but don't verify: --auth=off

    -q, --quiet            Do not print information on startup
    -h, --help             Show list of command-line options

Starts a KES gateway. The gateway address can be specified in the config file but
may be overwriten by the --addr flag. If omitted the address defaults to 0.0.0.0
(listen on all available network interfaces) and the port 7373.

The gateway's root identity can be specified in the config file but may be overwriten
by the --root flag. The IDENTITY should be a hash of a TLS public key encoded as hex
string. If the IDENTITY is not a public key hash e.g. --root="not-a-hash", the root
identity is effectively disabled.

The client TLS verification can be disabled by setting --auth=off. The gateway then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ export KES_ROOT_IDENTITY=$(kes tool identity of root.cert)
    $ kes gateway --key=private.key --cert=public.crt --root="$KES_ROOT_IDENTITY" --auth=off
`

func gatewayCmd(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, gatewayCmdUsage) }

	var (
		addrFlag     string
		configFlag   string
		rootFlag     string
		mlockFlag    bool
		tlsKeyFlag   string
		tlsCertFlag  string
		mtlsAuthFlag string
		quietFlag    quiet
	)
	cli.StringVar(&addrFlag, "addr", "0.0.0.0:7373", "The address of the gateway")
	cli.StringVar(&configFlag, "config", "", "Path to the gateway configuration file")
	cli.StringVar(&rootFlag, "root", "", "The identity of root - who can perform any operation")
	cli.BoolVar(&mlockFlag, "mlock", false, "Lock all allocated memory pages")
	cli.StringVar(&tlsKeyFlag, "key", "", "Path to the TLS private key")
	cli.StringVar(&tlsCertFlag, "cert", "", "Path to the TLS certificate")
	cli.StringVar(&mtlsAuthFlag, "auth", "on", "Controls how the gateway handles mTLS authentication")
	cli.Var(&quietFlag, "q", "Do not print information on startup")
	cli.Var(&quietFlag, "quiet", "Do not print information on startup")
	cli.Parse(args[1:])

	if cli.NArg() > 0 {
		stdlog.Fatal("Error: too many arguments")
	}
	if mlockFlag {
		if runtime.GOOS != "linux" {
			stdlog.Fatal("Error: cannot lock memory: syscall requires a linux system")
		}
		if err := mlockall(); err != nil {
			stdlog.Fatalf("Error: failed to lock memory: %v - See: 'man mlockall'", err)
		}
	}

	var ctx, cancelCtx = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	var config GatewayConfig
	if configFlag != "" {
		c, err := GatewayConfigFromFile(configFlag)
		if err != nil {
			stdlog.Fatalf("Error: failed to read config file: %v", err)
		}
		config = c
	}

	// Overwrite any config file entries with CLI flags
	// CLI flags take precedence.
	if config.Addr == "" {
		config.Addr = addrFlag
	}
	if config.Root == "" {
		if kes.Identity(rootFlag).IsUnknown() {
			stdlog.Fatal("Error: no root identity has been specified")
		}
		config.Root = kes.Identity(rootFlag)
	}
	if config.TLS.KeyPath == "" {
		if tlsKeyFlag == "" {
			stdlog.Fatal("Error: no private key file has been specified")
		}
		config.TLS.KeyPath = tlsKeyFlag
	}
	if config.TLS.CertPath == "" {
		if tlsCertFlag == "" {
			stdlog.Fatal("Error: no certificate file has been specified")
		}
		config.TLS.CertPath = tlsCertFlag
	}

	// Setup audit and error logging
	var (
		errorLog *xlog.Target
		auditLog *xlog.Target
	)
	switch strings.ToLower(config.Log.Error) {
	case "on":
		if isTerm(os.Stderr) { // If STDERR is a tty - write plain logs, not JSON.
			errorLog = xlog.NewTarget(os.Stderr)
		} else {
			errorLog = xlog.NewTarget(xlog.NewErrEncoder(os.Stderr))
		}
	case "off":
		errorLog = xlog.NewTarget(ioutil.Discard)
	default:
		stdlog.Fatalf("Error: %q is an invalid error log configuration", config.Log.Error)
	}
	switch strings.ToLower(config.Log.Audit) {
	case "on":
		auditLog = xlog.NewTarget(os.Stdout)
	case "off":
		auditLog = xlog.NewTarget(ioutil.Discard)
	default:
		stdlog.Fatalf("Error: %q is an invalid audit log configuration", config.Log.Audit)
	}
	auditLog.Log().SetFlags(0)

	// Setup TLS proxy handling, if configured
	var proxy *auth.TLSProxy
	if len(config.TLS.Proxy.Identities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.Proxy.Header.ClientCert),
		}
		if strings.ToLower(mtlsAuthFlag) != "off" {
			proxy.VerifyOptions = new(x509.VerifyOptions)
		}
		for _, identity := range config.TLS.Proxy.Identities {
			if !identity.IsUnknown() {
				proxy.Add(identity)
			}
		}
	}

	// Setup the policy system and assign policies to identities
	roles := &auth.Roles{
		Root: config.Root,
	}
	for name, policy := range config.Policies {
		p, err := kes.NewPolicy(policy.Allow...)
		if err != nil {
			stdlog.Fatalf("Error: policy %q contains invalid allow pattern: %v", name, err)
		}
		if err = p.Deny(policy.Deny...); err != nil {
			stdlog.Fatalf("Error: policy %q contains invalid deny pattern: %v", name, err)
		}
		roles.Set(name, p)

		for _, identity := range policy.Identities {
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

	// Connect to the backend keystore and create pre-defined keys, if configured
	store, err := config.KeyStore.Connect(quietFlag, errorLog.Log())
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
	for _, k := range config.Keys {
		bytes, err := sioutil.Random(key.Size)
		if err != nil {
			stdlog.Fatalf("Error: failed to create key %q: %v", k.Name, err)
		}

		if err = store.Create(ctx, k.Name, key.New(bytes)); err != nil && err != kes.ErrKeyExists {
			stdlog.Fatalf("Error: failed to create key %q: %v", k.Name, err)
		}
	}
	var manager = &key.Manager{
		CacheExpiryAny:    time.Duration(config.Cache.Expiry.Any),
		CacheExpiryUnused: time.Duration(config.Cache.Expiry.Unused),
		Store:             store,
	}

	// Setup the TLS server certificate
	certificate, err := xhttp.LoadCertificate(config.TLS.CertPath, config.TLS.KeyPath)
	if err != nil {
		stdlog.Fatalf("Error: failed to load TLS certificate: %v", err)
	}
	certificate.ErrorLog = errorLog

	// Setup the gateway metrics system
	var metrics = metric.New()
	errorLog.Add(metrics.ErrorEventCounter())
	auditLog.Add(metrics.AuditEventCounter())

	// Register all HTTP API handlers
	const MaxBody = 1 << 20 // 1 MiB
	var mux = http.NewServeMux()
	mux.Handle("/v1/key/create/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/create/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleCreateKey(manager)))))))))))
	mux.Handle("/v1/key/import/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/import/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleImportKey(manager)))))))))))
	mux.Handle("/v1/key/delete/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/key/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeleteKey(manager)))))))))))
	mux.Handle("/v1/key/generate/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/generate/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleGenerateKey(manager)))))))))))
	mux.Handle("/v1/key/encrypt/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/encrypt/*", xhttp.LimitRequestBody(MaxBody/2, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleEncryptKey(manager)))))))))))
	mux.Handle("/v1/key/decrypt/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/key/decrypt/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDecryptKey(manager)))))))))))
	mux.Handle("/v1/key/list/", xhttp.Timeout(15*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/key/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListKeys(manager)))))))))))

	mux.Handle("/v1/policy/write/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/policy/write/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleWritePolicy(roles)))))))))))
	mux.Handle("/v1/policy/read/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/read/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleReadPolicy(roles)))))))))))
	mux.Handle("/v1/policy/list/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/policy/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListPolicies(roles)))))))))))
	mux.Handle("/v1/policy/delete/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/policy/delete/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleDeletePolicy(roles)))))))))))

	mux.Handle("/v1/identity/assign/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodPost, xhttp.ValidatePath("/v1/identity/assign/*/*", xhttp.LimitRequestBody(MaxBody, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleAssignIdentity(roles)))))))))))
	mux.Handle("/v1/identity/list/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/identity/list/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleListIdentities(roles)))))))))))
	mux.Handle("/v1/identity/forget/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodDelete, xhttp.ValidatePath("/v1/identity/forget/*", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleForgetIdentity(roles)))))))))))

	mux.Handle("/v1/log/audit/trace", metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/log/audit/trace", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleTraceAuditLog(auditLog))))))))))
	mux.Handle("/v1/log/error/trace", metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/log/error/trace", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleTraceErrorLog(errorLog))))))))))

	mux.Handle("/v1/status", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/status", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleStatus(version, certificate, errorLog)))))))))))

	// Scrapping /v1/metrics should not change the metrics itself.
	// Further, scrapping /v1/metrics should, by default, not produce
	// an audit event. Monitoring systems will scrape the metrics endpoint
	// every few seconds - depending on their configuration - such that
	// the audit log will contain a lot of events simply pointing to the
	// monitoring system. Logging an audit event may be something that
	// can be enabled optionally.
	mux.Handle("/v1/metrics", xhttp.Timeout(10*time.Second, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/v1/metrics", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.EnforcePolicies(roles, xhttp.HandleMetrics(metrics))))))))

	mux.Handle("/version", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.RequireMethod(http.MethodGet, xhttp.ValidatePath("/version", xhttp.LimitRequestBody(0, xhttp.TLSProxy(proxy, xhttp.HandleVersion(version)))))))))) // /version is accessible to any identity
	mux.Handle("/", xhttp.Timeout(10*time.Second, metrics.Count(metrics.Latency(xhttp.AuditLog(auditLog.Log(), roles, xhttp.TLSProxy(proxy, http.NotFound))))))

	// Setup the HTTP server
	var server = http.Server{
		Addr:    config.Addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certificate.GetCertificate,
		},
		ErrorLog: errorLog.Log(),

		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - see timeout handler.
		IdleTimeout:       90 * time.Second,
	}
	if fips.Enabled { // Limit the supported cipher suites to the secure TLS 1.2/1.3 subset - i.e. only ECDHE key exchange and only AEAD ciphers.
		server.TLSConfig.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256, // TLS 1.3
			tls.TLS_AES_256_GCM_SHA384,

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // TLS 1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		}
	} else {
		server.TLSConfig.CipherSuites = []uint16{
			tls.TLS_AES_128_GCM_SHA256, // TLS 1.3
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // TLS 1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}
	switch strings.ToLower(mtlsAuthFlag) {
	case "on":
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "off":
		server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
	default:
		stdlog.Fatalf("Error: invalid option for --auth: %q", mtlsAuthFlag)
	}

	// Start background tasks to handle graceful shutdown requests and
	// TLS certificate renewal
	go func() {
		<-ctx.Done()

		shutdownContext, cancelShutdown := context.WithDeadline(context.Background(), time.Now().Add(800*time.Millisecond))
		err := server.Shutdown(shutdownContext)
		if cancelShutdown(); err == context.DeadlineExceeded {
			err = server.Close()
		}
		if err != nil {
			stdlog.Fatalf("Error: abnormal server shutdown: %v", err)
		}
	}()
	go certificate.ReloadAfter(ctx, 5*time.Minute) // 5min is a quite reasonable reload interval

	// Print the gateway startup message - Example:
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
	ip, port := serverAddr(config.Addr)
	kmsKind, kmsEndpoint := config.KeyStore.Description()
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	const margin = 10 // len("Endpoint: ")
	quietFlag.Print(blue.Sprint("Endpoint: "))
	quietFlag.Println(bold.Sprint(alignEndpoints(margin, interfaceIP4Addrs(), port)))
	quietFlag.Println()

	if r, err := hex.DecodeString(config.Root.String()); err == nil && len(r) == sha256.Size {
		quietFlag.Println(blue.Sprint("Root:    "), config.Root)
	} else {
		quietFlag.Println(blue.Sprint("Root:    "), "_     [ disabled ]")
	}
	if auth := strings.ToLower(mtlsAuthFlag); auth == "on" {
		quietFlag.Println(blue.Sprint("Auth:    "), color.New(color.Bold, color.FgGreen).Sprint("on "), color.GreenString("  [ only clients with trusted certificates can connect ]"))
	} else {
		quietFlag.Println(blue.Sprint("Auth:    "), color.New(color.Bold, color.FgYellow).Sprint("off"), color.YellowString("  [ any client can connect but policies still apply ]"))
	}
	quietFlag.Println()

	quietFlag.Println(blue.Sprint("Keys:    "), fmt.Sprintf("%s: %s", kmsKind, kmsEndpoint))
	quietFlag.Println()

	if runtime.GOOS == "windows" {
		quietFlag.Println(blue.Sprint("CLI:     "), bold.Sprintf("set KES_SERVER=https://%v:%s", ip, port))
		quietFlag.Println("         ", bold.Sprint("set KES_CLIENT_KEY=")+italic.Sprint("<client-private-key>")+`   // e.g. root.key`)
		quietFlag.Println("         ", bold.Sprint("set KES_CLIENT_CERT=")+italic.Sprint("<client-certificate>")+`  // e.g. root.cert`)
		quietFlag.Println("         ", bold.Sprint("kes --help"))
	} else {
		quietFlag.Println(blue.Sprint("CLI:     "), bold.Sprintf("export KES_SERVER=https://%v:%s", ip, port))
		quietFlag.Println("         ", bold.Sprint("export KES_CLIENT_KEY=")+italic.Sprint("<client-private-key>")+"   // e.g. $HOME/root.key")
		quietFlag.Println("         ", bold.Sprint("export KES_CLIENT_CERT=")+italic.Sprint("<client-certificate>")+"  // e.g. $HOME/root.cert")
		quietFlag.Println("         ", bold.Sprint("kes --help"))
	}

	// Start the HTTP server and listen for TLS connections
	if err := server.ListenAndServeTLS(config.TLS.CertPath, config.TLS.KeyPath); err != http.ErrServerClosed {
		stdlog.Fatalf("Error: failed to start server: %v", err)
	}
}
