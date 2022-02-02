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
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/internal/yml"
	"github.com/secure-io/sio-go/sioutil"
	"golang.org/x/crypto/ssh/terminal"
)

const serverCmdUsage = `Usage:
    kes server [options]

Options:
    --addr <IP:PORT>       The address of the server (default: 0.0.0.0:7373)
    --config <PATH>        Path to the server configuration file

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

The client TLS verification can be disabled by setting --auth=off. The server then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ kes server --config config.yml --auth =off
`

func server(args []string) {
	cli := flag.NewFlagSet(args[0], flag.ExitOnError)
	cli.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addrFlag     string
		configFlag   string
		mlockFlag    bool
		tlsKeyFlag   string
		tlsCertFlag  string
		mtlsAuthFlag string
		quietFlag    quiet
	)
	cli.StringVar(&addrFlag, "addr", "0.0.0.0:7373", "The address of the server")
	cli.StringVar(&configFlag, "config", "", "Path to the server configuration file")
	cli.BoolVar(&mlockFlag, "mlock", false, "Lock all allocated memory pages")
	cli.StringVar(&tlsKeyFlag, "key", "", "Path to the TLS private key")
	cli.StringVar(&tlsCertFlag, "cert", "", "Path to the TLS certificate")
	cli.StringVar(&mtlsAuthFlag, "auth", "on", "Controls how the server handles mTLS authentication")
	cli.Var(&quietFlag, "q", "Do not print information on startup")
	cli.Var(&quietFlag, "quiet", "Do not print information on startup")
	cli.Parse(args[1:])

	if cli.NArg() > 0 {
		stdlog.Fatal("Error: too many arguments")
	}
	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	if mlockFlag {
		if runtime.GOOS != "linux" {
			stdlog.Fatal("Error: cannot lock memory: syscall requires a linux system")
		}
		if err := mlockall(); err != nil {
			stdlog.Fatalf("Error: failed to lock memory: %v - See: 'man mlockall'", err)
		}
	}

	config, err := yml.ReadServerConfig(configFlag)
	if err != nil {
		stdlog.Fatalf("Error: failed to read config file: %v", err)
	}
	if config.Address.Value() == "" {
		config.Address.Set(addrFlag)
	}
	if config.TLS.PrivateKey.Value() == "" {
		config.TLS.PrivateKey.Set(tlsKeyFlag)
	}
	if config.TLS.Certificate.Value() == "" {
		config.TLS.Certificate.Set(tlsCertFlag)
	}
	if config.Admin.Identity.Value().IsUnknown() {
		stdlog.Fatal("Error: no admin identity specified")
	}
	if config.TLS.PrivateKey.Value() == "" {
		stdlog.Fatal("Error: no TLS private key specified")
	}
	if config.TLS.Certificate.Value() == "" {
		stdlog.Fatal("Error: no TLS certificate specified")
	}

	var errorLog *xlog.Target
	switch strings.ToLower(config.Log.Error.Value()) {
	case "on":
		if isTerm(os.Stderr) { // If STDERR is a tty - write plain logs, not JSON.
			errorLog = xlog.NewTarget(os.Stderr)
		} else {
			errorLog = xlog.NewTarget(xlog.NewErrEncoder(os.Stderr))
		}
	case "off":
		errorLog = xlog.NewTarget(ioutil.Discard)
	default:
		stdlog.Fatalf("Error: %q is an invalid error log configuration", config.Log.Error.Value())
	}

	var auditLog *xlog.Target
	switch strings.ToLower(config.Log.Audit.Value()) {
	case "on":
		auditLog = xlog.NewTarget(os.Stdout)
	case "off":
		auditLog = xlog.NewTarget(ioutil.Discard)
	default:
		stdlog.Fatalf("Error: %q is an invalid audit log configuration", config.Log.Audit.Value())
	}
	auditLog.Log().SetFlags(0)

	var proxy *auth.TLSProxy
	if len(config.TLS.Proxy.Identities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.Proxy.Header.ClientCert.Value()),
		}
		if strings.ToLower(mtlsAuthFlag) != "off" {
			proxy.VerifyOptions = new(x509.VerifyOptions)
		}
		for _, identity := range config.TLS.Proxy.Identities {
			if !identity.Value().IsUnknown() {
				proxy.Add(identity.Value())
			}
		}
	}

	policySet, err := policySetFromConfig(config)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
		return
	}
	identitySet, err := identitySetFromConfig(config)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
		return
	}
	store, err := connect(config, quietFlag, errorLog.Log())
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}
	cache := key.NewCache(store, &key.CacheConfig{
		Expiry:        config.Cache.Expiry.Any.Value(),
		ExpiryUnused:  config.Cache.Expiry.Unused.Value(),
		ExpiryOffline: config.Cache.Expiry.Offline.Value(),
	})
	defer cache.Stop()

	for _, k := range config.Keys {
		bytes, err := sioutil.Random(key.Size)
		if err != nil {
			stdlog.Fatalf("Error: failed to create key %q: %v", k.Name, err)
		}

		if err = store.Create(ctx, k.Name.Value(), key.New(bytes)); err != nil && err != kes.ErrKeyExists {
			stdlog.Fatalf("Error: failed to create key %q: %v", k.Name.Value(), err)
		}
	}

	certificate, err := xhttp.LoadCertificate(config.TLS.Certificate.Value(), config.TLS.PrivateKey.Value(), config.TLS.Password.Value())
	if err != nil {
		stdlog.Fatalf("Error: failed to load TLS certificate: %v", err)
	}
	certificate.ErrorLog = errorLog

	metrics := metric.New()
	errorLog.Add(metrics.ErrorEventCounter())
	auditLog.Add(metrics.AuditEventCounter())

	server := http.Server{
		Addr: config.Address.Value(),
		Handler: xhttp.NewServerMux(&xhttp.ServerConfig{
			Version:  version,
			Vault:    sys.NewStatelessVault(config.Admin.Identity.Value(), cache, policySet, identitySet),
			Proxy:    proxy,
			AuditLog: auditLog,
			ErrorLog: errorLog,
			Metrics:  metrics,
		}),
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certificate.GetCertificate,
		},
		ErrorLog: errorLog.Log(),

		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - see timeout handler.
		IdleTimeout:       90 * time.Second,
	}

	// Limit the supported cipher suites to the secure TLS 1.2/1.3 subset - i.e. only ECDHE key exchange and only AEAD ciphers.
	if fips.Enabled {
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
	go key.LogStoreStatus(ctx, cache, 1*time.Minute, errorLog.Log())

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
	ip, port := serverAddr(config.Address.Value())
	kmsKind, kmsEndpoint, err := description(config)
	if err != nil {
		stdlog.Fatalf("Error: %v", err)
	}

	const margin = 10 // len("Endpoint: ")
	quietFlag.Print(blue.Sprint("Endpoint: "))
	quietFlag.Println(bold.Sprint(alignEndpoints(margin, interfaceIP4Addrs(), port)))
	quietFlag.Println()

	if r, err := hex.DecodeString(config.Admin.Identity.Value().String()); err == nil && len(r) == sha256.Size {
		quietFlag.Println(blue.Sprint("Admin:   "), config.Admin.Identity.Value())
	} else {
		quietFlag.Println(blue.Sprint("Admin:   "), "_     [ disabled ]")
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

	// Start the HTTPS server. We pass a tls.Config.GetCertificate.
	// Therefore, we pass no certificate or private key file.
	// Passing the private key file here directly would break support
	// for encrypted private keys - which must be decrypted beforehand.
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
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

// ClearLine clears the last line written to STDOUT if
// STDOUT is a terminal that supports terminal control
// sequences.
//
// Otherwise, ClearLine just prints a empty newline.
func (q quiet) ClearLine() {
	if color.NoColor {
		q.Println()
	} else {
		q.Print(eraseLine)
	}
}

const (
	eraseLine = "\033[2K\r"
	moveUp    = "\033[1A"
)

// ClearMessage tries to erase the given message from STDOUT
// if STDOUT is a terminal that supports terminal control sequences.
//
// Otherwise, ClearMessage just prints an empty newline.
func (q quiet) ClearMessage(msg string) {
	if color.NoColor {
		q.Println()
		return
	}

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
