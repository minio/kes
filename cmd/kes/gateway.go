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
	"io/ioutil"
	"log"
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
	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/aws"
	"github.com/minio/kes/internal/azure"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/fortanix"
	"github.com/minio/kes/internal/fs"
	"github.com/minio/kes/internal/gcp"
	"github.com/minio/kes/internal/gemalto"
	"github.com/minio/kes/internal/generic"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/mem"
	"github.com/minio/kes/internal/metric"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/kes/internal/vault"
	"github.com/minio/kes/internal/yml"
)

type gatewayConfig struct {
	Address     string
	ConfigFile  string
	PrivateKey  string
	Certificate string
	TLSAuth     string
}

func startGateway(gConfig gatewayConfig) {
	var mlock bool
	if runtime.GOOS == "linux" {
		mlock = mlockall() == nil
	}

	ctx, cancelCtx := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancelCtx()

	config, err := yml.ReadServerConfig(gConfig.ConfigFile)
	if err != nil {
		cli.Fatalf("failed to read config file: %v", err)
	}
	if gConfig.Address != "" {
		config.Address.Set(gConfig.Address)
	}
	if gConfig.PrivateKey != "" {
		config.TLS.PrivateKey.Set(gConfig.PrivateKey)
	}
	if gConfig.Certificate != "" {
		config.TLS.Certificate.Set(gConfig.Certificate)
	}

	if config.Address.Value() == "" {
		config.Address.Set("0.0.0.0:7373")
	}
	if config.Admin.Identity.Value().IsUnknown() {
		cli.Fatal("no admin identity specified")
	}
	if config.TLS.PrivateKey.Value() == "" {
		cli.Fatal("no TLS private key specified")
	}
	if config.TLS.Certificate.Value() == "" {
		cli.Fatal("no TLS certificate specified")
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
		cli.Fatalf("%q is an invalid error log configuration", config.Log.Error.Value())
	}

	var auditLog *xlog.Target
	switch strings.ToLower(config.Log.Audit.Value()) {
	case "on":
		auditLog = xlog.NewTarget(os.Stdout)
	case "off":
		auditLog = xlog.NewTarget(ioutil.Discard)
	default:
		cli.Fatalf("%q is an invalid audit log configuration", config.Log.Audit.Value())
	}
	auditLog.Log().SetFlags(0)

	var proxy *auth.TLSProxy
	if len(config.TLS.Proxy.Identities) != 0 {
		proxy = &auth.TLSProxy{
			CertHeader: http.CanonicalHeaderKey(config.TLS.Proxy.Header.ClientCert.Value()),
		}
		if strings.ToLower(gConfig.TLSAuth) != "off" {
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
		cli.Fatal(err)
	}
	identitySet, err := identitySetFromConfig(config)
	if err != nil {
		cli.Fatal(err)
	}
	store, err := connect(config, errorLog.Log())
	if err != nil {
		cli.Fatal(err)
	}
	cache := key.NewCache(store, &key.CacheConfig{
		Expiry:        config.Cache.Expiry.Any.Value(),
		ExpiryUnused:  config.Cache.Expiry.Unused.Value(),
		ExpiryOffline: config.Cache.Expiry.Offline.Value(),
	})
	defer cache.Stop()

	for _, k := range config.Keys {
		var algorithm key.Algorithm
		if fips.Enabled || cpu.HasAESGCM() {
			algorithm = key.AES256_GCM_SHA256
		} else {
			algorithm = key.XCHACHA20_POLY1305
		}

		key, err := key.Random(algorithm, config.Admin.Identity.Value())
		if err != nil {
			cli.Fatalf("failed to create key %q: %v", k.Name, err)
		}
		if err = store.Create(ctx, k.Name.Value(), key); err != nil && !errors.Is(err, kes.ErrKeyExists) {
			cli.Fatalf("failed to create key %q: %v", k.Name.Value(), err)
		}
	}

	certificate, err := xhttp.LoadCertificate(config.TLS.Certificate.Value(), config.TLS.PrivateKey.Value(), config.TLS.Password.Value())
	if err != nil {
		cli.Fatalf("failed to load TLS certificate: %v", err)
	}
	certificate.ErrorLog = errorLog

	metrics := metric.New()
	errorLog.Add(metrics.ErrorEventCounter())
	auditLog.Add(metrics.AuditEventCounter())

	server := http.Server{
		Addr: config.Address.Value(),
		Handler: xhttp.NewGatewayMux(&xhttp.GatewayConfig{
			Keys:       cache,
			Policies:   policySet,
			Identities: identitySet,
			Proxy:      proxy,
			AuditLog:   auditLog,
			ErrorLog:   errorLog,
			Metrics:    metrics,
		}),
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			GetCertificate:   certificate.GetCertificate,
			CipherSuites:     fips.TLSCiphers(),
			CurvePreferences: fips.TLSCurveIDs(),
		},
		ErrorLog: errorLog.Log(),

		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      0 * time.Second, // explicitly set no write timeout - see timeout handler.
		IdleTimeout:       90 * time.Second,
	}

	switch strings.ToLower(gConfig.TLSAuth) {
	case "", "on":
		server.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	case "off":
		server.TLSConfig.ClientAuth = tls.RequireAnyClientCert
	default:
		cli.Fatalf("invalid option for --auth: %q", gConfig.TLSAuth)
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
	go certificate.ReloadAfter(ctx, 5*time.Minute) // 5min is a quite reasonable reload interval
	go key.LogStoreStatus(ctx, cache, 1*time.Minute, errorLog.Log())

	ip, port := serverAddr(config.Address.Value())
	ifaceIPs := listeningOnV4(ip)
	if len(ifaceIPs) == 0 {
		cli.Fatal("failed to listen on network interfaces")
	}
	kmsKind, kmsEndpoint, err := description(config)
	if err != nil {
		cli.Fatal(err)
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
		item.Render(fmt.Sprintf("%-10s", "KMS")),
		fmt.Sprintf("%s: %s", kmsKind, kmsEndpoint),
	)
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
	if r, err := hex.DecodeString(config.Admin.Identity.Value().String()); err == nil && len(r) == sha256.Size {
		cli.Println(
			item.Render(fmt.Sprintf("%-10s", "Admin")),
			config.Admin.Identity.Value(),
		)
	} else {
		cli.Println(
			item.Render(fmt.Sprintf("%-10s", "Admin")),
			fmt.Sprintf("%-12s", "_"),
			faint.Render("[ disabled ]"),
		)
	}
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

	// Start the HTTPS server. We pass a tls.Config.GetCertificate.
	// Therefore, we pass no certificate or private key file.
	// Passing the private key file here directly would break support
	// for encrypted private keys - which must be decrypted beforehand.
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		cli.Fatalf("failed to start server: %v", err)
	}
}

// connect tries to establish a connection to the KMS specified in the ServerConfig
func connect(config *yml.ServerConfig, errorLog *log.Logger) (key.Store, error) {
	switch {
	case config.KeyStore.Fs.Path.Value() != "":
		f, err := os.Stat(config.KeyStore.Fs.Path.Value())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("failed to open %q: %v", config.KeyStore.Fs.Path.Value(), err)
		}
		if err == nil && !f.IsDir() {
			return nil, fmt.Errorf("%q is not a directory", config.KeyStore.Fs.Path.Value())
		}
		if errors.Is(err, os.ErrNotExist) {
			if err = os.MkdirAll(config.KeyStore.Fs.Path.Value(), 0o700); err != nil {
				return nil, fmt.Errorf("failed to create directory %q: %v", config.KeyStore.Fs.Path.Value(), err)
			}
		}
		return &fs.Store{
			Dir:      config.KeyStore.Fs.Path.Value(),
			ErrorLog: errorLog,
		}, nil
	case config.KeyStore.Generic.Endpoint.Value() != "":
		genericStore := &generic.Store{
			Endpoint: config.KeyStore.Generic.Endpoint.Value(),
			KeyPath:  config.KeyStore.Generic.TLS.PrivateKey.Value(),
			CertPath: config.KeyStore.Generic.TLS.Certificate.Value(),
			CAPath:   config.KeyStore.Generic.TLS.CAPath.Value(),
			ErrorLog: errorLog,
		}
		if err := genericStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to generic KeyStore: %v", err)
		}
		return genericStore, nil
	case config.KeyStore.Vault.Endpoint.Value() != "":
		vaultStore, err := vault.Connect(context.Background(), &vault.Config{
			Endpoint:   config.KeyStore.Vault.Endpoint.Value(),
			Engine:     config.KeyStore.Vault.Engine.Value(),
			APIVersion: config.KeyStore.Vault.APIVersion.Value(),
			Prefix:     config.KeyStore.Vault.Prefix.Value(),
			Namespace:  config.KeyStore.Vault.Namespace.Value(),
			AppRole: vault.AppRole{
				Engine: config.KeyStore.Vault.AppRole.Engine.Value(),
				ID:     config.KeyStore.Vault.AppRole.ID.Value(),
				Secret: config.KeyStore.Vault.AppRole.Secret.Value(),
				Retry:  config.KeyStore.Vault.AppRole.Retry.Value(),
			},
			K8S: vault.Kubernetes{
				Engine: config.KeyStore.Vault.Kubernetes.Engine.Value(),
				Role:   config.KeyStore.Vault.Kubernetes.Role.Value(),
				JWT:    config.KeyStore.Vault.Kubernetes.JWT.Value(),
				Retry:  config.KeyStore.Vault.Kubernetes.Retry.Value(),
			},
			StatusPingAfter: config.KeyStore.Vault.Status.Ping.Value(),
			ErrorLog:        errorLog,
			ClientKeyPath:   config.KeyStore.Vault.TLS.PrivateKey.Value(),
			ClientCertPath:  config.KeyStore.Vault.TLS.Certificate.Value(),
			CAPath:          config.KeyStore.Vault.TLS.CAPath.Value(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Vault: %v", err)
		}
		return vaultStore, nil
	case config.KeyStore.Fortanix.SDKMS.Endpoint.Value() != "":
		fortanixStore := &fortanix.KeyStore{
			Endpoint: config.KeyStore.Fortanix.SDKMS.Endpoint.Value(),
			GroupID:  config.KeyStore.Fortanix.SDKMS.GroupID.Value(),
			APIKey:   fortanix.APIKey(config.KeyStore.Fortanix.SDKMS.Login.APIKey.Value()),
			ErrorLog: errorLog,
			CAPath:   config.KeyStore.Fortanix.SDKMS.TLS.CAPath.Value(),
		}
		if err := fortanixStore.Authenticate(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to connect to Fortanix SDKMS: %v", err)
		}
		return fortanixStore, nil
	case config.KeyStore.Aws.SecretsManager.Endpoint.Value() != "":
		awsStore := &aws.SecretsManager{
			Addr:     config.KeyStore.Aws.SecretsManager.Endpoint.Value(),
			Region:   config.KeyStore.Aws.SecretsManager.Region.Value(),
			KMSKeyID: config.KeyStore.Aws.SecretsManager.KmsKey.Value(),
			ErrorLog: errorLog,
			Login: aws.Credentials{
				AccessKey:    config.KeyStore.Aws.SecretsManager.Login.AccessKey.Value(),
				SecretKey:    config.KeyStore.Aws.SecretsManager.Login.SecretKey.Value(),
				SessionToken: config.KeyStore.Aws.SecretsManager.Login.SessionToken.Value(),
			},
		}
		if err := awsStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to AWS Secrets Manager: %v", err)
		}
		return awsStore, nil
	case config.KeyStore.GCP.SecretManager.ProjectID.Value() != "":
		scopes := make([]string, 0, len(config.KeyStore.GCP.SecretManager.Scopes))
		for _, scope := range config.KeyStore.GCP.SecretManager.Scopes {
			if scope.Value() != "" {
				scopes = append(scopes, scope.Value())
			}
		}
		gcpStore, err := gcp.Connect(context.Background(), &gcp.Config{
			Endpoint:  config.KeyStore.GCP.SecretManager.Endpoint.Value(),
			ProjectID: config.KeyStore.GCP.SecretManager.ProjectID.Value(),
			Scopes:    scopes,
			Credentials: gcp.Credentials{
				ClientID: config.KeyStore.GCP.SecretManager.Credentials.ClientID.Value(),
				Client:   config.KeyStore.GCP.SecretManager.Credentials.Client.Value(),
				KeyID:    config.KeyStore.GCP.SecretManager.Credentials.KeyID.Value(),
				Key:      config.KeyStore.GCP.SecretManager.Credentials.Key.Value(),
			},
			ErrorLog: errorLog,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to GCP SecretManager: %v", err)
		}
		return gcpStore, nil
	case config.KeyStore.Azure.KeyVault.Endpoint.Value() != "":
		azureStore := &azure.KeyVault{
			Endpoint: config.KeyStore.Azure.KeyVault.Endpoint.Value(),
			ErrorLog: errorLog,
		}
		switch c := config.KeyStore.Azure.KeyVault.Credentials; {
		case c.TenantID.Value() != "" || c.ClientID.Value() != "" || c.Secret.Value() != "":
			err := azureStore.AuthenticateWithCredentials(azure.Credentials{
				TenantID: config.KeyStore.Azure.KeyVault.Credentials.TenantID.Value(),
				ClientID: config.KeyStore.Azure.KeyVault.Credentials.ClientID.Value(),
				Secret:   config.KeyStore.Azure.KeyVault.Credentials.Secret.Value(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
			}
		case config.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value() != "":
			err := azureStore.AuthenticateWithIdentity(azure.ManagedIdentity{
				ClientID: config.KeyStore.Azure.KeyVault.ManagedIdentity.ClientID.Value(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to connect to Azure KeyVault: %v", err)
			}
		default:
			return nil, errors.New("failed to connect to Azure KeyVault: no client credentials or managed identity")
		}
		return azureStore, nil
	case config.KeyStore.Gemalto.KeySecure.Endpoint.Value() != "":
		gemaltoStore := &gemalto.KeySecure{
			Endpoint: config.KeyStore.Gemalto.KeySecure.Endpoint.Value(),
			CAPath:   config.KeyStore.Gemalto.KeySecure.TLS.CAPath.Value(),
			ErrorLog: errorLog,
			Login: gemalto.Credentials{
				Token:  config.KeyStore.Gemalto.KeySecure.Login.Token.Value(),
				Domain: config.KeyStore.Gemalto.KeySecure.Login.Domain.Value(),
				Retry:  config.KeyStore.Gemalto.KeySecure.Login.Retry.Value(),
			},
		}

		if err := gemaltoStore.Authenticate(); err != nil {
			return nil, fmt.Errorf("failed to connect to Gemalto KeySecure: %v", err)
		}
		return gemaltoStore, nil
	default:
		return &mem.Store{}, nil
	}
}

func description(config *yml.ServerConfig) (kind, endpoint string, err error) {
	switch {
	case config.KeyStore.Fs.Path.Value() != "":
		kind = "Filesystem"
		if endpoint, err = filepath.Abs(config.KeyStore.Fs.Path.Value()); err != nil {
			endpoint = config.KeyStore.Fs.Path.Value()
		}
	case config.KeyStore.Generic.Endpoint.Value() != "":
		kind = "Generic"
		endpoint = config.KeyStore.Generic.Endpoint.Value()
	case config.KeyStore.Vault.Endpoint.Value() != "":
		kind = "Hashicorp Vault"
		endpoint = config.KeyStore.Vault.Endpoint.Value()
	case config.KeyStore.Fortanix.SDKMS.Endpoint.Value() != "":
		kind = "Fortanix SDKMS"
		endpoint = config.KeyStore.Fortanix.SDKMS.Endpoint.Value()
	case config.KeyStore.Aws.SecretsManager.Endpoint.Value() != "":
		kind = "AWS SecretsManager"
		endpoint = config.KeyStore.Aws.SecretsManager.Endpoint.Value()
	case config.KeyStore.Gemalto.KeySecure.Endpoint.Value() != "":
		kind = "Gemalto KeySecure"
		endpoint = config.KeyStore.Gemalto.KeySecure.Endpoint.Value()
	case config.KeyStore.GCP.SecretManager.ProjectID.Value() != "":
		kind = "GCP SecretManager"
		endpoint = config.KeyStore.GCP.SecretManager.Endpoint.Value() + " | Project: " + config.KeyStore.GCP.SecretManager.ProjectID.Value()
	case config.KeyStore.Azure.KeyVault.Endpoint.Value() != "":
		kind = "Azure KeyVault"
		endpoint = config.KeyStore.Azure.KeyVault.Endpoint.Value()
	default:
		kind = "In-Memory"
		endpoint = "non-persistent"
	}
	return kind, endpoint, nil
}

// policySetFromConfig returns an in-memory PolicySet
// from the given ServerConfig.
func policySetFromConfig(config *yml.ServerConfig) (auth.PolicySet, error) {
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
			CreatedBy: config.Admin.Identity.Value(),
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
func identitySetFromConfig(config *yml.ServerConfig) (auth.IdentitySet, error) {
	identities := &identitySet{
		admin:     config.Admin.Identity.Value(),
		createdAt: time.Now().UTC(),
		roles:     map[kes.Identity]auth.IdentityInfo{},
	}

	for name, policy := range config.Policies {
		for _, id := range policy.Identities {
			if id.Value().IsUnknown() {
				continue
			}

			if id.Value() == config.Admin.Identity.Value() {
				return nil, fmt.Errorf("identity %q is already an admin identity", id.Value())
			}
			if _, ok := identities.roles[id.Value()]; ok {
				return nil, fmt.Errorf("identity %q is already assigned", id.Value())
			}
			for _, proxyID := range config.TLS.Proxy.Identities {
				if id.Value() == proxyID.Value() {
					return nil, fmt.Errorf("identity %q is already a TLS proxy identity", id.Value())
				}
			}
			identities.roles[id.Value()] = auth.IdentityInfo{
				Policy:    name,
				CreatedAt: time.Now().UTC(),
				CreatedBy: config.Admin.Identity.Value(),
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

func (i *identitySet) Admin(ctx context.Context) (kes.Identity, error) { return i.admin, nil }

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
		return auth.IdentityInfo{}, auth.ErrIdentityNotFound
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
