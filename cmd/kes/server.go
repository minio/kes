// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/kesconf"
	kesdk "github.com/minio/kms-go/kes"
	flag "github.com/spf13/pflag"
)

const serverCmdUsage = `Usage:
    kes server [options]

Options:
    --addr <[ip]:port>       The network interface the KES server will listen on.
                             The default is '0.0.0.0:7373' which causes the server
                             to listen on all available network interfaces.

    --config <file>          Path to the KES server config file.

    --dev                    Start the KES server in development mode. The server
                             uses a volatile in-memory key store.

    -h, --help               Show list of command-line options


MinIO KES is a high-performance distributed key management server.
It is a stateless, self-contained server that uses a separate key
store as persistence layer. KES servers can be added or removed at
any point in time to scale out infinitely.

   Quick Start: https://github.com/minio/kes#quick-start
   Docs:        https://min.io/docs/kes/
	
Examples:
  1. Start a new KES server on '127.0.0.1:7373' in development mode.
     $ kes server --dev

  2. Start a new KES server with a confg file on '127.0.0.1:7000'.
     $ kes server --addr :7000 --config ./kes/config.yml
`

func serverCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, serverCmdUsage) }

	var (
		addrFlag     string
		configFlag   string
		tlsKeyFlag   string
		tlsCertFlag  string
		mtlsAuthFlag string
		devFlag      bool
	)
	cmd.StringVar(&addrFlag, "addr", "", "The address of the server")
	cmd.StringVar(&configFlag, "config", "", "Path to the server configuration file")
	cmd.StringVar(&tlsKeyFlag, "key", "", "Path to the TLS private key")
	cmd.StringVar(&tlsCertFlag, "cert", "", "Path to the TLS certificate")
	cmd.StringVar(&mtlsAuthFlag, "auth", "", "Controls how the server handles mTLS authentication")
	cmd.BoolVar(&devFlag, "dev", false, "Start the KES server in development mode")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes server --help'", err)
	}

	warnPrefix := tui.NewStyle().Foreground(tui.Color("#ac0000")).Render("WARNING:")
	if tlsKeyFlag != "" {
		fmt.Fprintln(os.Stderr, warnPrefix, "'--key' flag is deprecated and no longer honored. Specify the private key in the config file")
	}
	if tlsCertFlag != "" {
		fmt.Fprintln(os.Stderr, warnPrefix, "'--cert' flag is deprecated and no longer honored. Specify the certificate  in the config file")
	}
	if mtlsAuthFlag != "" {
		fmt.Fprintln(os.Stderr, warnPrefix, "'--auth' flag is deprecated and no longer honored. Specify the client certificate verification in the config file")
	}

	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}

	if devFlag {
		if addrFlag == "" {
			addrFlag = "0.0.0.0:7373"
		}
		if configFlag != "" {
			cli.Fatal("'--config' flag is not supported in development mode")
		}

		if err := startDevServer(addrFlag); err != nil {
			cli.Fatal(err)
		}
		return
	}

	if err := startServer(addrFlag, configFlag); err != nil {
		cli.Fatal(err)
	}
}

func startServer(addrFlag, configFlag string) error {
	var memLocked bool
	if runtime.GOOS == "linux" {
		memLocked = mlockall() == nil
		defer munlockall()
	}

	info, err := sys.ReadBinaryInfo()
	if err != nil {
		return err
	}

	// Read the config file before looking up the
	// local network interfaces. We may not know the
	// server addr yet since a user may not specified
	// one on the command line.
	rawConfig, err := kesconf.ReadFile(configFlag)
	if err != nil {
		return err
	}
	switch {
	case addrFlag != "":
		// Nothing to do, addrFlag is set
	case rawConfig.Addr != "":
		addrFlag = rawConfig.Addr
	default:
		addrFlag = "0.0.0.0:7373"
	}

	host, port, err := net.SplitHostPort(addrFlag)
	if err != nil {
		return err
	}
	ip := net.IPv4zero
	if host != "" {
		if ip = net.ParseIP(host); ip == nil {
			return fmt.Errorf("'%s' is not a valid IP address", host)
		}
	}
	ifaceIPs, err := lookupInterfaceIPs(ip)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	conf, err := rawConfig.Config(ctx)
	if err != nil {
		return err
	}
	defer conf.Keys.Close()

	srv := &kes.Server{}
	conf.Cache = configureCache(conf.Cache)
	if rawConfig.Log != nil {
		srv.LogFormat = rawConfig.Log.LogFormat
		srv.ErrLevel.Set(rawConfig.Log.ErrLevel)
		srv.AuditLevel.Set(rawConfig.Log.AuditLevel)
	}
	sighup := make(chan os.Signal, 10)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	startupMessage := func(conf *kes.Config) *strings.Builder {
		blue := tui.NewStyle().Foreground(tui.Color("#268BD2"))
		faint := tui.NewStyle().Faint(true)

		buf := &strings.Builder{}
		fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Version"), info.Version, faint.Render("commit="+info.CommitID))
		fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Runtime"), fmt.Sprintf("%s %s/%s", info.Runtime, runtime.GOOS, runtime.GOARCH), faint.Render("compiler="+info.Compiler))
		fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("License"), "AGPLv3", faint.Render("https://www.gnu.org/licenses/agpl-3.0.html"))
		fmt.Fprintf(buf, "%-33s %-12s 2015-%d  %s\n", blue.Render("Copyright"), "MinIO, Inc.", time.Now().Year(), faint.Render("https://min.io"))
		fmt.Fprintln(buf)
		fmt.Fprintf(buf, "%-33s %v\n", blue.Render("KMS"), conf.Keys)
		fmt.Fprintf(buf, "%-33s · https://%s\n", blue.Render("API"), net.JoinHostPort(ifaceIPs[0].String(), port))
		for _, ifaceIP := range ifaceIPs[1:] {
			fmt.Fprintf(buf, "%-11s · https://%s\n", " ", net.JoinHostPort(ifaceIP.String(), port))
		}

		fmt.Fprintln(buf)
		fmt.Fprintf(buf, "%-33s https://min.io/docs/kes\n", blue.Render("Docs"))

		fmt.Fprintln(buf)
		if _, err := hex.DecodeString(conf.Admin.String()); err == nil {
			fmt.Fprintf(buf, "%-33s %s\n", blue.Render("Admin"), conf.Admin)
		} else {
			fmt.Fprintf(buf, "%-33s <disabled>\n", blue.Render("Admin"))
		}
		fmt.Fprintf(buf, "%-33s error=stderr level=%s format=%s\n", blue.Render("Logs"), srv.ErrLevel.Level(), srv.LogFormat)
		if srv.AuditLevel.Level() <= slog.LevelInfo {
			fmt.Fprintf(buf, "%-11s audit=stdout level=%s format=%s\n", " ", srv.AuditLevel.Level(), srv.LogFormat)
		}
		if memLocked {
			fmt.Fprintf(buf, "%-33s %s\n", blue.Render("MLock"), "enabled")
		}
		return buf
	}

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				fmt.Fprintln(os.Stderr, "SIGHUP signal received. Reloading configuration...")

				file, err := kesconf.ReadFile(configFlag)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload server config: %v\n", err)
					continue
				}
				config, err := file.Config(ctx)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload server config: %v\n", err)
					continue
				}
				config.Cache = configureCache(config.Cache)

				closer, err := srv.Update(config)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update server configuration: %v\n", err)
					continue
				}
				if file.Log != nil {
					srv.LogFormat = file.Log.LogFormat
					srv.ErrLevel.Set(file.Log.ErrLevel)
					srv.AuditLevel.Set(file.Log.AuditLevel)
				}

				if err = closer.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to close previous keystore connections: %v\n", err)
				}
				buf := startupMessage(config)
				fmt.Fprintln(buf)
				fmt.Fprintln(buf, "=> Reloading configuration after SIGHUP signal completed.")
				fmt.Println(buf.String())
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				file, err := kesconf.ReadFile(configFlag)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload TLS configuration: %v\n", err)
					continue
				}
				conf, err := file.TLSConfig()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload TLS configuration: %v\n", err)
					continue
				}
				if err = srv.UpdateTLS(conf); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update TLS configuration: %v\n", err)
				}
			}
		}
	}(ctx)

	buf := startupMessage(conf)
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "=> Server is up and running...")
	fmt.Println(buf.String())

	if err = srv.ListenAndStart(ctx, addrFlag, conf); err != nil {
		return err
	}
	fmt.Println("\n=> Stopping server... Goodbye.")
	return nil
}

func startDevServer(addr string) error {
	info, err := sys.ReadBinaryInfo()
	if err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.IPv4zero
	if host != "" {
		if ip = net.ParseIP(host); ip == nil {
			return fmt.Errorf("'%s' is not a valid IP address", host)
		}
	}
	ifaceIPs, err := lookupInterfaceIPs(ip)
	if err != nil {
		return err
	}
	srvCert, err := generateDevServerCertificate(ifaceIPs...)
	if err != nil {
		return err
	}

	apiKey, err := kesdk.GenerateAPIKey(nil)
	if err != nil {
		return err
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAnyClientCert,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	conf := &kes.Config{
		Admin: apiKey.Identity(),
		TLS:   tlsConf,
		Cache: &kes.CacheConfig{
			Expiry:        5 * time.Minute,
			ExpiryUnused:  30 * time.Second,
			ExpiryOffline: 0,
		},
		Keys: &kes.MemKeyStore{},
	}
	srv := &kes.Server{}

	blue := tui.NewStyle().Foreground(tui.Color("#268BD2"))
	faint := tui.NewStyle().Faint(true)

	buf := &strings.Builder{}
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Version"), info.Version, faint.Render("commit="+info.CommitID))
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Runtime"), fmt.Sprintf("%s %s/%s", info.Runtime, runtime.GOOS, runtime.GOARCH), faint.Render("compiler="+info.Compiler))
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("License"), "AGPLv3", faint.Render("https://www.gnu.org/licenses/agpl-3.0.html"))
	fmt.Fprintf(buf, "%-33s %-12s 2015-%d  %s\n", blue.Render("Copyright"), "MinIO, Inc.", time.Now().Year(), faint.Render("https://min.io"))
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "%-33s %v\n", blue.Render("KMS"), conf.Keys)
	fmt.Fprintf(buf, "%-33s · https://%s\n", blue.Render("API"), net.JoinHostPort(ifaceIPs[0].String(), port))
	for _, ifaceIP := range ifaceIPs[1:] {
		fmt.Fprintf(buf, "%-11s · https://%s\n", " ", net.JoinHostPort(ifaceIP.String(), port))
	}
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "%-33s https://min.io/docs/kes\n", blue.Render("Docs"))
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "%-33s %s\n", blue.Render("API Key"), apiKey.String())
	fmt.Fprintf(buf, "%-33s %s\n", blue.Render("Admin"), apiKey.Identity())
	fmt.Fprintf(buf, "%-33s error=stderr level=%s format=%s\n", blue.Render("Logs"), srv.ErrLevel.Level(), srv.LogFormat)
	fmt.Fprintf(buf, "%-11s audit=stdout level=%s format=%s\n", " ", srv.AuditLevel.Level(), srv.LogFormat)
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "=> Server is up and running...")
	fmt.Println(buf.String())

	if err := srv.ListenAndStart(ctx, addr, conf); err != nil {
		return err
	}
	fmt.Println("\n=> Stopping server... Goodbye.")
	return nil
}

// configureCache sets default values for each cache config option
// as documented in: https://github.com/minio/kes/blob/master/server-config.yaml
func configureCache(c *kes.CacheConfig) *kes.CacheConfig {
	if c == nil {
		c = &kes.CacheConfig{}
	}
	if c.Expiry == 0 {
		c.Expiry = 5 * time.Minute
	}
	if c.ExpiryUnused == 0 {
		c.Expiry = 30 * time.Second
	}
	return c
}

// lookupInterfaceIPs returns a list of IP addrs for which a listener
// listening on listenerIP is reachable. If listenerIP is not
// unspecified (0.0.0.0) it returns []net.IP{listenerIP}.
//
// Otherwise, lookupInterfaceIPs iterates over all available network
// interfaces excluding unicast and multicast IPs. It prefers IPv4
// addrs and only returns IPv6 addrs if there are no IPv4 addrs.
func lookupInterfaceIPs(listenerIP net.IP) ([]net.IP, error) {
	if !listenerIP.IsUnspecified() {
		return []net.IP{listenerIP}, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ipv4s, ipv6s []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 { // interface is down
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
				continue
			}

			if ipv4 := ip.To4(); ipv4 != nil && !slices.ContainsFunc(ipv4s, func(x net.IP) bool { return ipv4.Equal(x) }) {
				ipv4s = append(ipv4s, ipv4)
			} else if !slices.ContainsFunc(ipv6s, func(x net.IP) bool { return ip.Equal(x) }) {
				ipv6s = append(ipv6s, ip)
			}
		}
	}

	if len(ipv4s) > 0 { // prefer IPv4 addrs, if any
		return ipv4s, nil
	}
	if len(ipv6s) > 0 {
		return ipv6s, nil
	}
	return nil, errors.New("no IPv4 or IPv6 addresses available")
}

func generateDevServerCertificate(ipSANs ...net.IP) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().UTC(),
		NotAfter:  time.Now().UTC().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		IPAddresses:           ipSANs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	privPKCS8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privPKCS8}),
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	return cert, nil
}
