// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/fips"
	xhttp "github.com/minio/kes/internal/http"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/internal/sys/fs"
	flag "github.com/spf13/pflag"
)

const serverCmdUsage = `Usage:
    kes server [options]

Options:
    --addr <IP:PORT>         The address of the server (default: 0.0.0.0:7373)
    --config <PATH>          Path to the server configuration file

    --key <PATH>             Path to the TLS private key. It takes precedence over
                             the config file
    --cert <PATH>            Path to the TLS certificate. It takes precedence over
                             the config file

    --auth {on|off}          Controls how the server handles mTLS authentication.
                             By default, the server requires a client certificate
                             and verifies that certificate has been issued by a
                             trusted CA.
                             Valid options are:
                                Require and verify      : --auth=on (default)
                                Require but don't verify: --auth=off

    -h, --help               Show list of command-line options

Starts a KES server. The server address can be specified in the config file but
may be overwritten by the --addr flag. If omitted the IP defaults to 0.0.0.0 and
the PORT to 7373.

The client TLS verification can be disabled by setting --auth=off. The server then
accepts arbitrary client certificates but still maps them to policies. So, it disables
authentication but not authorization.

Examples:
    $ kes server --config config.yml --auth =off
`

type serverConfig struct {
	Address     string
	ConfigPath  string
	PrivateKey  string
	Certificate string
	TLSAuth     string
}

func serverCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addrFlag     string
		configFlag   string
		tlsKeyFlag   string
		tlsCertFlag  string
		mtlsAuthFlag string
	)
	cmd.StringVar(&addrFlag, "addr", "", "The address of the server")
	cmd.StringVar(&configFlag, "config", "", "Path to the server configuration file")
	cmd.StringVar(&tlsKeyFlag, "key", "", "Path to the TLS private key")
	cmd.StringVar(&tlsCertFlag, "cert", "", "Path to the TLS certificate")
	cmd.StringVar(&mtlsAuthFlag, "auth", "", "Controls how the server handles mTLS authentication")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes server --help'", err)
	}

	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}
	if cmd.NArg() == 0 {
		startGateway(gatewayConfig{
			Address:     addrFlag,
			ConfigFile:  configFlag,
			PrivateKey:  tlsKeyFlag,
			Certificate: tlsCertFlag,
			TLSAuth:     mtlsAuthFlag,
		})
	} else {
		config := serverConfig{
			Address:     addrFlag,
			ConfigPath:  configFlag,
			PrivateKey:  tlsKeyFlag,
			Certificate: tlsCertFlag,
			TLSAuth:     mtlsAuthFlag,
		}
		startServer(cmd.Arg(0), config)
	}
}

func startServer(path string, sConfig serverConfig) {
	var mlock bool
	if runtime.GOOS == "linux" {
		mlock = mlockall() == nil
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	init, err := fs.ReadInitConfig(filepath.Join(path, ".init"))
	if err != nil {
		cli.Fatalf("failed to initialize vault: %v", err)
	}
	if sConfig.Address != "" {
		init.Address.Set(sConfig.Address)
	}
	if sConfig.PrivateKey != "" {
		init.Address.Set(sConfig.PrivateKey)
	}
	if sConfig.Certificate != "" {
		init.Certificate.Set(sConfig.Certificate)
	}
	switch strings.ToLower(sConfig.TLSAuth) {
	case "on":
		init.VerifyClientCerts.Set(true)
	case "off":
		init.VerifyClientCerts.Set(false)
	}

	if init.Address.Value() == "" {
		init.Address.Set("0.0.0.0:7373")
	}
	if init.PrivateKey.Value() == "" {
		cli.Fatal("no TLS private key specified")
	}
	if init.Certificate.Value() == "" {
		cli.Fatal("no TLS certificate specified")
	}

	var (
		errorLog *xlog.Target
		auditLog = xlog.NewTarget(ioutil.Discard)
	)
	if isTerm(os.Stderr) { // If STDERR is a tty - write plain logs, not JSON.
		errorLog = xlog.NewTarget(os.Stderr)
	} else {
		errorLog = xlog.NewTarget(xlog.NewErrEncoder(os.Stderr))
	}
	auditLog.Log().SetFlags(0)

	certificate, err := xhttp.LoadCertificate(init.Certificate.Value(), init.PrivateKey.Value(), init.Password.Value())
	if err != nil {
		cli.Fatalf("failed to load TLS certificate: %v", err)
	}
	certificate.ErrorLog = errorLog

	if c, _ := certificate.GetCertificate(nil); c != nil && c.Leaf != nil {
		if len(c.Leaf.DNSNames) == 0 && len(c.Leaf.IPAddresses) == 0 {
			// Support for TLS certificates with a subject CN but without any SAN
			// has been removed in Go 1.15. Ref: https://go.dev/doc/go1.15#commonname
			// Therefore, we require at least one SAN for the server certificate.
			cli.Fatal("failed to load TLS certificate: certificate does not contain any DNS or IP address as SAN")
		}
	}

	clientAuth := tls.RequireAnyClientCert
	if init.VerifyClientCerts.Value() {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	var proxy *auth.TLSProxy
	if len(init.ProxyIdentities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(init.ProxyClientCert.Value()),
		}
		if clientAuth == tls.RequireAndVerifyClientCert || clientAuth == tls.VerifyClientCertIfGiven {
			proxy.VerifyOptions = new(x509.VerifyOptions)
		}
		for _, identity := range init.ProxyIdentities {
			if !identity.Value().IsUnknown() {
				proxy.Add(identity.Value())
			}
		}
	}

	vault, err := fs.Open(path, errorLog.Log())
	if err != nil {
		cli.Fatalf("failed to initialize vault: %v", err)
	}

	metrics := metric.New()
	errorLog.Add(metrics.ErrorEventCounter())
	auditLog.Add(metrics.AuditEventCounter())

	server := http.Server{
		Addr: init.Address.Value(),
		Handler: xhttp.NewServerMux(&xhttp.ServerConfig{
			Vault:    vault,
			Proxy:    proxy,
			AuditLog: auditLog,
			ErrorLog: errorLog,
			Metrics:  metrics,
		}),
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			GetCertificate:   certificate.GetCertificate,
			CipherSuites:     fips.TLSCiphers(),
			CurvePreferences: fips.TLSCurveIDs(),
			ClientAuth:       clientAuth,
		},
		ErrorLog: errorLog.Log(),

		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - see timeout handler.
		IdleTimeout:       90 * time.Second,
	}

	go func() {
		<-ctx.Done()

		shutdownContext, cancelShutdown := context.WithDeadline(context.Background(), time.Now().Add(800*time.Millisecond))
		err := server.Shutdown(shutdownContext)
		if cancelShutdown(); err == context.DeadlineExceeded {
			err = server.Close()
		}
		if err != nil {
			cli.Fatalf("abnormal server shutdown: %v", err)
		}
	}()

	// By default, reload the certificate every 5m.
	reloadCertInterval := time.NewTicker(5 * time.Minute)
	defer reloadCertInterval.Stop()
	go xhttp.ReloadCertificate(ctx, certificate, reloadCertInterval.C)

	// Also reload the certificate when receiving a SIGHUP signal.
	// SIGHUP is only available on unix systems. Therefore excluding windows.
	if runtime.GOOS != "windows" {
		sighup := make(chan os.Signal, 10)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Reset(syscall.SIGHUP)
		go xhttp.ReloadCertificate(ctx, certificate, sighup)
	}

	ip, port := serverAddr(init.Address.Value())
	ifaceIPs := listeningOnV4(ip)
	if len(ifaceIPs) == 0 {
		cli.Fatal("failed to listen on network interfaces")
	}

	var faint, item, green, red, yellow tui.Style
	if isTerm(os.Stdout) {
		faint = faint.Faint(true)
		item = item.Foreground(tui.Color("#2e42d1")).Bold(true)
		green = green.Foreground(tui.Color("#00a700"))
		red = red.Foreground(tui.Color("#a70000"))
		yellow = yellow.Foreground(tui.Color("#fede00"))
	}
	cli.Println(
		item.Render(fmt.Sprintf("%-10s", "Copyright")),
		fmt.Sprintf("%-12s", "MinIO, Inc."),
		faint.Render("https://min.io"),
	)
	cli.Println(
		item.Render(fmt.Sprintf("%-10s", "License")),
		fmt.Sprintf("%-12s", "GNU AGPLv3"),
		faint.Render("https://www.gnu.org/licenses/agpl-3.0.html"),
	)
	cli.Println(
		item.Render(fmt.Sprintf("%-10s", "Version")),
		fmt.Sprintf("%-12s", sys.BinaryInfo().Version),
		faint.Render(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)),
	)

	cli.Println()
	cli.Println(
		item.Render(fmt.Sprintf("%-10s", "Endpoints")),
		fmt.Sprintf("https://%s:%s", ifaceIPs[0], port),
	)
	for _, ifaceIP := range ifaceIPs[1:] {
		cli.Println(
			fmt.Sprintf("%-10s", " "),
			fmt.Sprintf("https://%s:%s", ifaceIP, port),
		)
	}

	cli.Println()
	if auth := server.TLSConfig.ClientAuth; auth == tls.VerifyClientCertIfGiven || auth == tls.RequireAndVerifyClientCert {
		cli.Println(
			item.Render(fmt.Sprintf("%-10s", "mTLS")),
			green.Render(fmt.Sprintf("%-12s", "verify")),
			faint.Render("Only clients with trusted certificates can connect"),
		)
	} else {
		cli.Println(
			item.Render(fmt.Sprintf("%-10s", "mTLS")),
			yellow.Render(fmt.Sprintf("%-12s", "skip verify")),
			faint.Render("Client certificates are not verified"),
		)
	}

	if runtime.GOOS == "linux" {
		if mlock {
			cli.Println(
				item.Render(fmt.Sprintf("%-10s", "Mem Lock")),
				green.Render(fmt.Sprintf("%-12s", "on")),
				faint.Render("RAM pages will not be swapped to disk"),
			)
		} else {
			cli.Println(
				item.Render(fmt.Sprintf("%-10s", "Mem Lock")),
				red.Render(fmt.Sprintf("%-12s", "off")),
				faint.Render("Failed to lock RAM pages. Consider granting CAP_IPC_LOCK"),
			)
		}
	} else {
		cli.Println(
			item.Render(fmt.Sprintf("%-10s", "Mem Lock")),
			red.Render(fmt.Sprintf("%-12s", "off")),
			faint.Render(fmt.Sprintf("Not supported on %s/%s", runtime.GOOS, runtime.GOARCH)),
		)
	}

	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		cli.Fatalf("failed to start server: %v", err)
	}
}

// listeningOnV4 returns a list of the system IPv4 interface
// addresses an TCP/IP listener with the given IP is listening
// on.
//
// In particular, a TCP/IP listener listening on the pseudo
// address 0.0.0.0 listens on all network interfaces while
// a listener on a specific IP only listens on the network
// interface with that IP address.
func listeningOnV4(ip net.IP) []net.IP {
	if !ip.IsUnspecified() {
		return []net.IP{ip}
	}
	// We listen on the pseudo-address: 0.0.0.0
	// The TCP/IP listener is listening on all available
	// network interfaces.
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
		cli.Fatalf("invalid server address: %q", addr)
	}
	if host == "" {
		host = "0.0.0.0"
	}

	ip = net.ParseIP(host)
	if ip == nil {
		cli.Fatalf("invalid server address: %q", addr)
	}
	return ip, port
}
