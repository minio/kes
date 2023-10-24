// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes"
	kesdk "github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/kv"
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

type serverArgs struct {
	Address     string
	ConfigFile  string
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

	if cmd.NArg() > 0 {
		cli.Fatal("too many arguments. See 'kes server --help'")
	}

	var memLocked bool
	if runtime.GOOS == "linux" {
		memLocked = mlockall() == nil
		defer munlockall()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	addr, config, err := readServerConfig(ctx, serverArgs{
		Address:     addrFlag,
		ConfigFile:  configFlag,
		PrivateKey:  tlsKeyFlag,
		Certificate: tlsCertFlag,
		TLSAuth:     mtlsAuthFlag,
	})
	if err != nil {
		cli.Fatal(err)
	}

	srv := &kes.Server{}
	srv.ErrLevel.Set(slog.LevelWarn)

	sighup := make(chan os.Signal, 10)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)

	go func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				fmt.Fprintln(os.Stderr, "SIGHUP signal received. Reloading configuration...")
				_, config, err := readServerConfig(ctx, serverArgs{
					Address:     addrFlag,
					ConfigFile:  configFlag,
					PrivateKey:  tlsKeyFlag,
					Certificate: tlsCertFlag,
					TLSAuth:     mtlsAuthFlag,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload server config: %v\n", err)
					continue
				}
				config.Keys = &kes.MemKeyStore{}

				closer, err := srv.Update(config)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update server configuration: %v\n", err)
					continue
				}

				if err = closer.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to close previous keystore connections: %v\n", err)
				}
				buf, err := printServerStartup(srv, addrFlag, config, memLocked)
				if err == nil {
					fmt.Fprintln(buf)
					fmt.Fprintln(buf, "=> Reloading configuration after SIGHUP signal completed.")
					fmt.Println(buf.String())
				}
			}
		}
	}(ctx)

	go func(ctx context.Context) {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, config, err := readServerConfig(ctx, serverArgs{
					Address:     addrFlag,
					ConfigFile:  configFlag,
					PrivateKey:  tlsKeyFlag,
					Certificate: tlsCertFlag,
					TLSAuth:     mtlsAuthFlag,
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to reload TLS configuration: %v\n", err)
					continue
				}
				if err = srv.UpdateTLS(config.TLS); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to update TLS configuration: %v\n", err)
				}
			}
		}
	}(ctx)

	buf, err := printServerStartup(srv, addr, config, memLocked)
	if err != nil {
		cli.Fatal(err)
	}
	fmt.Fprintln(buf)
	fmt.Fprintln(buf, "=> Server is up and running...")
	fmt.Println(buf.String())

	if err = srv.ListenAndStart(ctx, addrFlag, config); err != nil {
		cli.Fatal(err)
	}
	fmt.Println("\n=> Stopping server... Goodbye.")
}

func printServerStartup(srv *kes.Server, addr string, config *kes.Config, memLocked bool) (*strings.Builder, error) {
	info, err := sys.ReadBinaryInfo()
	if err != nil {
		return nil, err
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.IPv4zero
	if host != "" {
		if ip = net.ParseIP(host); ip == nil {
			return nil, fmt.Errorf("'%s' is not a valid IP address", host)
		}
	}
	ifaceIPs, err := lookupInterfaceIPs(ip)
	if err != nil {
		return nil, err
	}

	keys := config.Keys.(adapter)

	blue := tui.NewStyle().Foreground(tui.Color("#268BD2"))
	faint := tui.NewStyle().Faint(true)

	buf := &strings.Builder{}
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Version"), info.Version, faint.Render("commit="+info.CommitID))
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("Runtime"), fmt.Sprintf("%s %s/%s", info.Runtime, runtime.GOOS, runtime.GOARCH), faint.Render("compiler="+info.Compiler))
	fmt.Fprintf(buf, "%-33s %-23s %s\n", blue.Render("License"), "AGPLv3", faint.Render("https://www.gnu.org/licenses/agpl-3.0.html"))
	fmt.Fprintf(buf, "%-33s %-12s 2015-%d  %s\n", blue.Render("Copyright"), "MinIO, Inc.", time.Now().Year(), faint.Render("https://min.io"))
	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "%-33s %s: %s\n", blue.Render("KMS"), keys.Type, keys.Endpoint)
	fmt.Fprintf(buf, "%-33s · https://%s\n", blue.Render("API"), net.JoinHostPort(ifaceIPs[0].String(), port))
	for _, ifaceIP := range ifaceIPs[1:] {
		fmt.Fprintf(buf, "%-11s · https://%s\n", " ", net.JoinHostPort(ifaceIP.String(), port))
	}

	fmt.Fprintln(buf)
	fmt.Fprintf(buf, "%-33s https://min.io/docs/kes\n", blue.Render("Docs"))

	fmt.Fprintln(buf)
	if _, err := hex.DecodeString(config.Admin.String()); err == nil {
		fmt.Fprintf(buf, "%-33s %s\n", blue.Render("Admin"), config.Admin)
	} else {
		fmt.Fprintf(buf, "%-33s <disabled>\n", blue.Render("Admin"))
	}
	fmt.Fprintf(buf, "%-33s error=stderr level=%s\n", blue.Render("Logs"), srv.ErrLevel.Level())
	if srv.AuditLevel.Level() <= slog.LevelInfo {
		fmt.Fprintf(buf, "%-11s audit=stdout level=%s\n", " ", srv.AuditLevel.Level())
	}
	if memLocked {
		fmt.Fprintf(buf, "%-33s %s\n", blue.Render("MLock"), "enabled")
	}
	return buf, nil
}

func readServerConfig(ctx context.Context, args serverArgs) (string, *kes.Config, error) {
	file, err := os.Open(args.ConfigFile)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	config, err := edge.ReadServerConfigYAML(file)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read config file: %v", err)
	}
	if err = file.Close(); err != nil {
		return "", nil, err
	}

	if args.Address != "" {
		config.Addr = args.Address
	}
	if args.PrivateKey != "" {
		config.TLS.PrivateKey = args.PrivateKey
	}
	if args.Certificate != "" {
		config.TLS.Certificate = args.Certificate
	}

	// Set config defaults
	if config.Addr == "" {
		config.Addr = "0.0.0.0:7373"
	}
	if config.Cache.Expiry == 0 {
		config.Cache.Expiry = 5 * time.Minute
	}
	if config.Cache.ExpiryUnused == 0 {
		config.Cache.ExpiryUnused = 30 * time.Second
	}

	// Verify config
	if config.Admin.IsUnknown() {
		return "", nil, errors.New("no admin identity specified")
	}
	if config.TLS.PrivateKey == "" {
		return "", nil, errors.New("no TLS private key specified")
	}
	if config.TLS.Certificate == "" {
		return "", nil, errors.New("no TLS certificate specified")
	}

	certificate, err := https.CertificateFromFile(config.TLS.Certificate, config.TLS.PrivateKey, config.TLS.Password)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read TLS certificate: %v", err)
	}
	if certificate.Leaf != nil {
		if len(certificate.Leaf.DNSNames) == 0 && len(certificate.Leaf.IPAddresses) == 0 {
			// Support for TLS certificates with a subject CN but without any SAN
			// has been removed in Go 1.15. Ref: https://go.dev/doc/go1.15#commonname
			// Therefore, we require at least one SAN for the server certificate.
			return "", nil, fmt.Errorf("invalid TLS certificate: certificate does not contain any DNS or IP address as SAN")
		}
	}

	var rootCAs *x509.CertPool
	if config.TLS.CAPath != "" {
		rootCAs, err = https.CertPoolFromFile(config.TLS.CAPath)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read TLS CA certificates: %v", err)
		}
	}

	var errorLog slog.Handler
	var auditLog kes.AuditHandler
	if config.Log.Error {
		errorLog = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	if config.Log.Audit {
		auditLog = &kes.AuditLogHandler{Handler: slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})}
	}

	// TODO(aead): support TLS proxies

	var apiConfig map[string]kes.RouteConfig
	if config.API != nil && len(config.API.Paths) > 0 {
		apiConfig = make(map[string]kes.RouteConfig, len(config.API.Paths))
		for k, v := range config.API.Paths {
			k = strings.TrimSpace(k) // Ensure that the API path starts with a '/'
			if !strings.HasPrefix(k, "/") {
				k = "/" + k
			}

			if _, ok := apiConfig[k]; ok {
				return "", nil, fmt.Errorf("ambiguous API configuration for '%s'", k)
			}
			apiConfig[k] = kes.RouteConfig{
				Timeout:          v.Timeout,
				InsecureSkipAuth: v.InsecureSkipAuth,
			}
		}
	}

	policies := make(map[string]kes.Policy, len(config.Policies))
	for name, policy := range config.Policies {
		p := kes.Policy{
			Allow:      make(map[string]kesdk.Rule, len(policy.Allow)),
			Deny:       make(map[string]kesdk.Rule, len(policy.Deny)),
			Identities: slices.Clone(policy.Identities),
		}
		for _, pattern := range policy.Allow {
			p.Allow[pattern] = kesdk.Rule{}
		}
		for _, pattern := range policy.Deny {
			p.Deny[pattern] = kesdk.Rule{}
		}
		policies[name] = p
	}

	kmsKind, kmsEndpoint, err := description(config)
	if err != nil {
		return "", nil, err
	}

	store, err := config.KeyStore.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	keys := adapter{
		store:    store,
		Type:     kmsKind,
		Endpoint: kmsEndpoint,
	}

	return config.Addr, &kes.Config{
		Admin: config.Admin,
		TLS: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
			RootCAs:      rootCAs,
			ClientAuth:   tls.RequestClientCert,
		},
		Cache: &kes.CacheConfig{
			Expiry:        config.Cache.Expiry,
			ExpiryUnused:  config.Cache.ExpiryUnused,
			ExpiryOffline: config.Cache.ExpiryOffline,
		},
		Keys:     keys,
		Policies: policies,
		Routes:   apiConfig,
		ErrorLog: errorLog,
		AuditLog: auditLog,
	}, nil
}

// TODO(aead): temp adapater - remove once keystores are ported to KeyStore interface
type adapter struct {
	Type string

	Endpoint string

	store kv.Store[string, []byte]
}

func (a adapter) Status(ctx context.Context) (kes.KeyStoreState, error) {
	s, err := a.store.Status(ctx)
	if err != nil {
		return kes.KeyStoreState{}, err
	}
	return kes.KeyStoreState{
		Latency: s.Latency,
	}, nil
}

func (a adapter) Create(ctx context.Context, name string, value []byte) error {
	return a.store.Create(ctx, name, value)
}

func (a adapter) Delete(ctx context.Context, name string) error {
	return a.store.Delete(ctx, name)
}

func (a adapter) Get(ctx context.Context, name string) ([]byte, error) {
	return a.store.Get(ctx, name)
}

func (a adapter) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	if n == 0 {
		return []string{}, prefix, nil
	}

	iter, err := a.store.List(ctx)
	if err != nil {
		return nil, "", err
	}
	defer iter.Close()

	var keys []string
	for key, ok := iter.Next(); ok; key, ok = iter.Next() {
		keys = append(keys, key)
	}
	if err = iter.Close(); err != nil {
		return nil, "", err
	}
	slices.Sort(keys)

	if prefix == "" {
		if n < 0 || n >= len(keys) {
			return keys, "", nil
		}
		return keys[:n], keys[n], nil
	}

	i := slices.IndexFunc(keys, func(key string) bool { return strings.HasPrefix(key, prefix) })
	if i < 0 {
		return []string{}, "", nil
	}

	for j, key := range keys[i:] {
		if !strings.HasPrefix(key, prefix) {
			return keys[i : i+j], "", nil
		}
		if n > 0 && j == n {
			return keys[i : i+j], key, nil
		}
	}
	return keys[i:], "", nil
}

func (a adapter) Close() error { return a.store.Close() }

func description(config *edge.ServerConfig) (kind string, endpoint string, err error) {
	if config.KeyStore == nil {
		return "", "", errors.New("no KMS backend specified")
	}

	switch kms := config.KeyStore.(type) {
	case *edge.FSKeyStore:
		kind = "Filesystem"
		if abs, err := filepath.Abs(kms.Path); err == nil {
			endpoint = abs
		} else {
			endpoint = kms.Path
		}
	case *edge.VaultKeyStore:
		kind = "Hashicorp Vault"
		endpoint = kms.Endpoint
	case *edge.FortanixKeyStore:
		kind = "Fortanix SDKMS"
		endpoint = kms.Endpoint
	case *edge.AWSSecretsManagerKeyStore:
		kind = "AWS SecretsManager"
		endpoint = kms.Endpoint
	case *edge.KeySecureKeyStore:
		kind = "Gemalto KeySecure"
		endpoint = kms.Endpoint
	case *edge.GCPSecretManagerKeyStore:
		kind = "GCP SecretManager"
		endpoint = "Project: " + kms.ProjectID
	case *edge.AzureKeyVaultKeyStore:
		kind = "Azure KeyVault"
		endpoint = kms.Endpoint
	case *edge.EntrustKeyControlKeyStore:
		kind = "Entrust KeyControl"
		endpoint = kms.Endpoint
	default:
		return "", "", fmt.Errorf("unknown KMS backend %T", kms)
	}
	return kind, endpoint, nil
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
