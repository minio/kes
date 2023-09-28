// Copyright 2022 - MinIO, Inc. All rights reserved.
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
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes-go"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/internal/api"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/keystore"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
)

type gatewayConfig struct {
	Address     string
	ConfigFile  string
	PrivateKey  string
	Certificate string
	TLSAuth     string
}

func startGateway(cliConfig gatewayConfig) {
	var mlock bool
	if runtime.GOOS == "linux" {
		mlock = mlockall() == nil
	}

	if isTerm(os.Stderr) {
		style := tui.NewStyle().Foreground(tui.Color("#ac0000")) // red
		log.Default().SetPrefix(style.Render("Error: "))
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	config, err := loadGatewayConfig(cliConfig)
	if err != nil {
		cli.Fatal(err)
	}
	tlsConfig, err := newTLSConfig(config, cliConfig.TLSAuth)
	if err != nil {
		cli.Fatal(err)
	}
	gwConfig, err := newGatewayConfig(ctx, config, tlsConfig)
	if err != nil {
		cli.Fatal(err)
	}

	buffer, err := gatewayMessage(config, tlsConfig, mlock)
	if err != nil {
		cli.Fatal(err)
	}
	cli.Println(buffer.String())

	server := https.NewServer(&https.Config{
		Addr:      config.Addr,
		Handler:   api.NewEdgeRouter(gwConfig),
		TLSConfig: tlsConfig,
	})
	go func(ctx context.Context) {
		if runtime.GOOS == "windows" {
			return
		}

		sighup := make(chan os.Signal, 10)
		signal.Notify(sighup, syscall.SIGHUP)
		defer signal.Stop(sighup)

		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				cli.Println("SIGHUP signal received. Reloading configuration...")
				config, err := loadGatewayConfig(cliConfig)
				if err != nil {
					log.Printf("failed to read server config: %v", err)
					continue
				}
				tlsConfig, err := newTLSConfig(config, cliConfig.TLSAuth)
				if err != nil {
					log.Printf("failed to initialize TLS config: %v", err)
					continue
				}
				gwConfig, err := newGatewayConfig(ctx, config, tlsConfig)
				if err != nil {
					log.Printf("failed to initialize server API: %v", err)
					continue
				}
				err = server.Update(&https.Config{
					Addr:      config.Addr,
					Handler:   api.NewEdgeRouter(gwConfig),
					TLSConfig: tlsConfig,
					Cancel:    func() { gwConfig.Keys.Close() },
				})
				if err != nil {
					log.Printf("failed to update server configuration: %v", err)
					continue
				}
				buffer, err := gatewayMessage(config, tlsConfig, mlock)
				if err != nil {
					log.Print(err)
					cli.Println("Reloading configuration after SIGHUP signal completed.")
				} else {
					cli.Println(buffer.String())
				}
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
				tlsConfig, err := newTLSConfig(config, cliConfig.TLSAuth)
				if err != nil {
					log.Printf("failed to reload TLS configuration: %v", err)
					continue
				}
				if err = server.UpdateTLS(tlsConfig); err != nil {
					log.Printf("failed to update TLS configuration: %v", err)
				}
			}
		}
	}(ctx)

	if err := server.Start(ctx); err != nil && err != http.ErrServerClosed {
		cli.Fatal(err)
	}
}

func description(config *edge.ServerConfig) (kind string, endpoint []string, err error) {
	if config.KeyStore == nil {
		return "", nil, errors.New("no KMS backend specified")
	}

	switch kms := config.KeyStore.(type) {
	case *edge.FSKeyStore:
		kind = "Filesystem"
		if abs, err := filepath.Abs(kms.Path); err == nil {
			endpoint = []string{abs}
		} else {
			endpoint = []string{kms.Path}
		}
	case *edge.KESKeyStore:
		kind = "KES"
		endpoint = kms.Endpoints
	case *edge.VaultKeyStore:
		kind = "Hashicorp Vault"
		endpoint = []string{kms.Endpoint}
	case *edge.FortanixKeyStore:
		kind = "Fortanix SDKMS"
		endpoint = []string{kms.Endpoint}
	case *edge.AWSSecretsManagerKeyStore:
		kind = "AWS SecretsManager"
		endpoint = []string{kms.Endpoint}
	case *edge.KeySecureKeyStore:
		kind = "Gemalto KeySecure"
		endpoint = []string{kms.Endpoint}
	case *edge.GCPSecretManagerKeyStore:
		kind = "GCP SecretManager"
		endpoint = []string{"Project: " + kms.ProjectID}
	case *edge.AzureKeyVaultKeyStore:
		kind = "Azure KeyVault"
		endpoint = []string{kms.Endpoint}
	case *edge.EntrustKeyControlKeyStore:
		kind = "Entrust KeyControl"
		endpoint = []string{kms.Endpoint}
	default:
		return "", nil, fmt.Errorf("unknown KMS backend %T", kms)
	}
	return kind, endpoint, nil
}

// policySetFromConfig returns an in-memory PolicySet
// from the given ServerConfig.
func policySetFromConfig(config *edge.ServerConfig) (auth.PolicySet, error) {
	policies := &policySet{
		policies: make(map[string]*auth.Policy),
	}
	for name, policy := range config.Policies {
		if _, ok := policies.policies[name]; ok {
			return nil, fmt.Errorf("policy %q already exists", name)
		}

		policies.policies[name] = &auth.Policy{
			Allow:     policy.Allow,
			Deny:      policy.Deny,
			CreatedAt: time.Now().UTC(),
			CreatedBy: config.Admin,
		}
	}
	return policies, nil
}

type policySet struct {
	lock     sync.RWMutex
	policies map[string]*auth.Policy
}

var _ auth.PolicySet = (*policySet)(nil) // compiler check

func (p *policySet) Set(_ context.Context, name string, policy *auth.Policy) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.policies[name] = policy
	return nil
}

func (p *policySet) Get(_ context.Context, name string) (*auth.Policy, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	policy, ok := p.policies[name]
	if !ok {
		return nil, kes.ErrPolicyNotFound
	}
	return policy, nil
}

func (p *policySet) Delete(_ context.Context, name string) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	delete(p.policies, name)
	return nil
}

func (p *policySet) List(_ context.Context) (auth.PolicyIterator, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	names := make([]string, 0, len(p.policies))
	for name := range p.policies {
		names = append(names, name)
	}
	return &policyIterator{
		values: names,
	}, nil
}

type policyIterator struct {
	values  []string
	current string
}

var _ auth.PolicyIterator = (*policyIterator)(nil) // compiler check

func (i *policyIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *policyIterator) Name() string { return i.current }

func (i *policyIterator) Close() error { return nil }

// identitySetFromConfig returns an in-memory IdentitySet
// from the given ServerConfig.
func identitySetFromConfig(config *edge.ServerConfig) (auth.IdentitySet, error) {
	identities := &identitySet{
		admin:     config.Admin,
		createdAt: time.Now().UTC(),
		roles:     map[kes.Identity]auth.IdentityInfo{},
	}

	for name, policy := range config.Policies {
		for _, id := range policy.Identities {
			if id.IsUnknown() {
				continue
			}

			if id == config.Admin {
				return nil, fmt.Errorf("identity %q is already an admin identity", id)
			}
			if _, ok := identities.roles[id]; ok {
				return nil, fmt.Errorf("identity %q is already assigned", id)
			}
			for _, proxyID := range config.TLS.Proxies {
				if id == proxyID {
					return nil, fmt.Errorf("identity %q is already a TLS proxy identity", id)
				}
			}
			identities.roles[id] = auth.IdentityInfo{
				Policy:    name,
				CreatedAt: time.Now().UTC(),
				CreatedBy: config.Admin,
			}
		}
	}
	return identities, nil
}

type identitySet struct {
	admin     kes.Identity
	createdAt time.Time

	lock  sync.RWMutex
	roles map[kes.Identity]auth.IdentityInfo
}

var _ auth.IdentitySet = (*identitySet)(nil) // compiler check

func (i *identitySet) Admin(context.Context) (kes.Identity, error) { return i.admin, nil }

func (i *identitySet) SetAdmin(context.Context, kes.Identity) error {
	return kes.NewError(http.StatusNotImplemented, "cannot set admin identity")
}

func (i *identitySet) Assign(_ context.Context, policy string, identity kes.Identity) error {
	if i.admin == identity {
		return kes.NewError(http.StatusBadRequest, "identity is root")
	}
	i.lock.Lock()
	defer i.lock.Unlock()

	i.roles[identity] = auth.IdentityInfo{
		Policy:    policy,
		CreatedAt: time.Now().UTC(),
		CreatedBy: i.admin,
	}
	return nil
}

func (i *identitySet) Get(_ context.Context, identity kes.Identity) (auth.IdentityInfo, error) {
	if identity == i.admin {
		return auth.IdentityInfo{
			IsAdmin:   true,
			CreatedAt: i.createdAt,
		}, nil
	}
	i.lock.RLock()
	defer i.lock.RUnlock()

	policy, ok := i.roles[identity]
	if !ok {
		return auth.IdentityInfo{}, kes.ErrIdentityNotFound
	}
	return policy, nil
}

func (i *identitySet) Delete(_ context.Context, identity kes.Identity) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	delete(i.roles, identity)
	return nil
}

func (i *identitySet) List(_ context.Context) (auth.IdentityIterator, error) {
	i.lock.RLock()
	defer i.lock.RUnlock()

	values := make([]kes.Identity, 0, len(i.roles))
	for identity := range i.roles {
		values = append(values, identity)
	}
	return &identityIterator{
		values: values,
	}, nil
}

type identityIterator struct {
	values  []kes.Identity
	current kes.Identity
}

var _ auth.IdentityIterator = (*identityIterator)(nil) // compiler check

func (i *identityIterator) Next() bool {
	next := len(i.values) > 0
	if next {
		i.current = i.values[0]
		i.values = i.values[1:]
	}
	return next
}

func (i *identityIterator) Identity() kes.Identity { return i.current }

func (i *identityIterator) Close() error { return nil }

func loadGatewayConfig(gConfig gatewayConfig) (*edge.ServerConfig, error) {
	file, err := os.Open(gConfig.ConfigFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config, err := edge.ReadServerConfigYAML(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	if gConfig.Address != "" {
		config.Addr = gConfig.Address
	}
	if gConfig.PrivateKey != "" {
		config.TLS.PrivateKey = gConfig.PrivateKey
	}
	if gConfig.Certificate != "" {
		config.TLS.Certificate = gConfig.Certificate
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
		return nil, errors.New("no admin identity specified")
	}
	if config.TLS.PrivateKey == "" {
		return nil, errors.New("no TLS private key specified")
	}
	if config.TLS.Certificate == "" {
		return nil, errors.New("no TLS certificate specified")
	}
	return config, nil
}

func newTLSConfig(config *edge.ServerConfig, auth string) (*tls.Config, error) {
	certificate, err := https.CertificateFromFile(config.TLS.Certificate, config.TLS.PrivateKey, config.TLS.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS certificate: %v", err)
	}
	if certificate.Leaf != nil {
		if len(certificate.Leaf.DNSNames) == 0 && len(certificate.Leaf.IPAddresses) == 0 {
			// Support for TLS certificates with a subject CN but without any SAN
			// has been removed in Go 1.15. Ref: https://go.dev/doc/go1.15#commonname
			// Therefore, we require at least one SAN for the server certificate.
			return nil, fmt.Errorf("invalid TLS certificate: certificate does not contain any DNS or IP address as SAN")
		}
	}

	var rootCAs *x509.CertPool
	if config.TLS.CAPath != "" {
		rootCAs, err = https.CertPoolFromFile(config.TLS.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS CA certificates: %v", err)
		}
	}
	var clientAuth tls.ClientAuthType
	switch strings.ToLower(auth) {
	case "", "on":
		clientAuth = tls.RequireAndVerifyClientCert
		if config.API != nil {
			for _, api := range config.API.Paths {
				if api.InsecureSkipAuth {
					clientAuth = tls.VerifyClientCertIfGiven
					break
				}
			}
		}
	case "off":
		clientAuth = tls.RequireAnyClientCert
		if config.API != nil {
			for _, api := range config.API.Paths {
				if api.InsecureSkipAuth {
					clientAuth = tls.RequestClientCert
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("invalid option for --auth: %s", auth)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   clientAuth,
		RootCAs:      rootCAs,
		ClientCAs:    rootCAs,

		MinVersion:       tls.VersionTLS12,
		CipherSuites:     fips.TLSCiphers(),
		CurvePreferences: fips.TLSCurveIDs(),
	}, nil
}

func newGatewayConfig(ctx context.Context, config *edge.ServerConfig, tlsConfig *tls.Config) (*api.EdgeRouterConfig, error) {
	rConfig := &api.EdgeRouterConfig{}

	if config.Log.Error {
		rConfig.ErrorLog = log.New(os.Stderr, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	} else {
		rConfig.ErrorLog = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime|log.Lmsgprefix)
	}
	if config.Log.Audit {
		rConfig.AuditLog = log.New(os.Stdout, "", 0)
	} else {
		rConfig.AuditLog = log.New(io.Discard, "", 0)
	}

	if len(config.TLS.Proxies) != 0 {
		rConfig.Proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.ForwardCertHeader),
		}
		if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
			rConfig.Proxy.VerifyOptions = &x509.VerifyOptions{
				Roots: tlsConfig.RootCAs,
			}
		}
		for _, identity := range config.TLS.Proxies {
			if !identity.IsUnknown() {
				rConfig.Proxy.Add(identity)
			}
		}
	}

	if config.API != nil && len(config.API.Paths) > 0 {
		rConfig.APIConfig = make(map[string]api.Config, len(config.API.Paths))
		for k, v := range config.API.Paths {
			k = strings.TrimSpace(k) // Ensure that the API path starts with a '/'
			if !strings.HasPrefix(k, "/") {
				k = "/" + k
			}

			if _, ok := rConfig.APIConfig[k]; ok {
				return nil, fmt.Errorf("ambiguous API configuration for '%s'", k)
			}
			rConfig.APIConfig[k] = api.Config{
				Timeout:          v.Timeout,
				InsecureSkipAuth: v.InsecureSkipAuth,
			}
		}
	}

	var err error
	rConfig.Policies, err = policySetFromConfig(config)
	if err != nil {
		return nil, err
	}
	rConfig.Identities, err = identitySetFromConfig(config)
	if err != nil {
		return nil, err
	}

	conn, err := config.KeyStore.Connect(ctx)
	if err != nil {
		return nil, err
	}
	rConfig.Keys = keystore.NewCache(ctx, conn, &keystore.CacheConfig{
		Expiry:        config.Cache.Expiry,
		ExpiryUnused:  config.Cache.ExpiryUnused,
		ExpiryOffline: config.Cache.ExpiryOffline,
	})

	for _, k := range config.Keys {
		var algorithm kes.KeyAlgorithm
		if fips.Enabled || cpu.HasAESGCM() {
			algorithm = kes.AES256_GCM_SHA256
		} else {
			algorithm = kes.XCHACHA20_POLY1305
		}

		key, err := key.Random(algorithm, config.Admin)
		if err != nil {
			return nil, fmt.Errorf("failed to create key '%s': %v", k.Name, err)
		}
		if err = rConfig.Keys.Create(ctx, k.Name, key); err != nil && !errors.Is(err, kes.ErrKeyExists) {
			return nil, fmt.Errorf("failed to create key '%s': %v", k.Name, err)
		}
	}

	rConfig.Metrics = metric.New()
	rConfig.AuditLog.Add(rConfig.Metrics.AuditEventCounter())
	rConfig.ErrorLog.Add(rConfig.Metrics.ErrorEventCounter())
	return rConfig, nil
}

func gatewayMessage(config *edge.ServerConfig, tlsConfig *tls.Config, mlock bool) (*cli.Buffer, error) {
	ip, port := serverAddr(config.Addr)
	ifaceIPs := listeningOnV4(ip)
	if len(ifaceIPs) == 0 {
		return nil, errors.New("failed to listen on network interfaces")
	}
	kmsKind, kmsEndpoints, err := description(config)
	if err != nil {
		return nil, err
	}

	var faint, item, green, red tui.Style
	if isTerm(os.Stdout) {
		faint = faint.Faint(true)
		item = item.Foreground(tui.Color("#2e42d1")).Bold(true)
		green = green.Foreground(tui.Color("#00a700"))
		red = red.Foreground(tui.Color("#a70000"))
	}

	buffer := new(cli.Buffer)
	buffer.Stylef(item, "%-12s", "Copyright").Sprintf("%-22s", "MinIO, Inc.").Styleln(faint, "https://min.io")
	buffer.Stylef(item, "%-12s", "License").Sprintf("%-22s", "GNU AGPLv3").Styleln(faint, "https://www.gnu.org/licenses/agpl-3.0.html")
	buffer.Stylef(item, "%-12s", "Version").Sprintf("%-22s", sys.BinaryInfo().Version).Stylef(faint, "%s/%s\n", runtime.GOOS, runtime.GOARCH)
	buffer.Sprintln()
	buffer.Stylef(item, "%-12s", "KMS").Sprintf("%s: %s\n", kmsKind, kmsEndpoints[0])
	for _, endpoint := range kmsEndpoints[1:] {
		buffer.Sprintf("%-12s", " ").Sprint(strings.Repeat(" ", len(kmsKind))).Sprintf("  %s\n", endpoint)
	}
	buffer.Stylef(item, "%-12s", "Endpoints").Sprintf("https://%s:%s\n", ifaceIPs[0], port)
	for _, ifaceIP := range ifaceIPs[1:] {
		buffer.Sprintf("%-12s", " ").Sprintf("https://%s:%s\n", ifaceIP, port)
	}
	buffer.Sprintln()
	if r, err := hex.DecodeString(config.Admin.String()); err == nil && len(r) == sha256.Size {
		buffer.Stylef(item, "%-12s", "Admin").Sprintln(config.Admin)
	} else {
		buffer.Stylef(item, "%-12s", "Admin").Sprintf("%-22s", "_").Styleln(faint, "[ disabled ]")
	}
	if tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		buffer.Stylef(item, "%-12s", "Mutual TLS").Sprint("on").Styleln(faint, "Verify client certificates")
	}
	switch {
	case runtime.GOOS == "linux" && mlock:
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(green, "%-22s", "on").Styleln(faint, "RAM pages will not be swapped to disk")
	case runtime.GOOS == "linux":
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(red, "%-22s", "off").Styleln(faint, "Failed to lock RAM pages. Consider granting CAP_IPC_LOCK")
	default:
		buffer.Stylef(item, "%-12s", "Mem Lock").Stylef(red, "%-22s", "off").Stylef(faint, "Not supported on %s/%s\n", runtime.GOOS, runtime.GOARCH)
	}
	return buffer, nil
}
