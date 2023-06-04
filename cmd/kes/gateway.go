// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/minio/kes/edge"
	"github.com/minio/kes/edge/edgeconf"
	"github.com/minio/kes/internal/cli"
	"github.com/minio/kes/internal/keystore/aws"
	"github.com/minio/kes/internal/keystore/azure"
	"github.com/minio/kes/internal/keystore/entrust"
	"github.com/minio/kes/internal/keystore/fortanix"
	"github.com/minio/kes/internal/keystore/fs"
	"github.com/minio/kes/internal/keystore/gcp"
	"github.com/minio/kes/internal/keystore/gemalto"
	kesstore "github.com/minio/kes/internal/keystore/kes"
	"github.com/minio/kes/internal/keystore/vault"
	"github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/sys"
)

func startEdgeServer(filename, addr string) {
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

	store, config, err := connectEdgeServer(ctx, filename, addr)
	if err != nil {
		cli.Fatal(err)
	}

	buffer, err := gatewayMessage(store, config, mlock)
	if err != nil {
		cli.Fatal(err)
	}
	cli.Println(buffer.String())

	var srv edge.Server
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

				store, config, err := connectEdgeServer(ctx, filename, addr)
				if err != nil {
					log.Printf("failed to reload server config: %v", err)
					continue
				}
				if err = srv.Update(store, config); err != nil {
					log.Printf("failed to update server config: %v", err)
					continue
				}

				buffer, err := gatewayMessage(store, config, mlock)
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
				store, config, err := connectEdgeServer(ctx, filename, addr)
				if err != nil {
					log.Printf("failed to reload server config: %v", err)
					continue
				}
				if err = srv.Update(store, config); err != nil {
					log.Printf("failed to update server config: %v", err)
					continue
				}
			}
		}
	}(ctx)

	if err := srv.Start(ctx, store, config); err != nil && err != http.ErrServerClosed {
		cli.Fatal(err)
	}
}

func description(store edge.KeyStore) (kind string, endpoint []string, err error) {
	if store == nil {
		return "", nil, errors.New("no KMS backend specified")
	}

	switch kms := store.(type) {
	case *fs.FS:
		kind = "Filesystem"
		if abs, err := filepath.Abs(kms.Path()); err == nil {
			endpoint = []string{abs}
		} else {
			endpoint = []string{kms.Path()}
		}
	case *kesstore.Store:
		kind = "KES"
		endpoint = kms.Endpoints()
	case *vault.Store:
		kind = "Hashicorp Vault"
		endpoint = []string{kms.Endpoint()}
	case *fortanix.Store:
		kind = "Fortanix SDKMS"
		endpoint = []string{kms.Endpoint()}
	case *aws.Store:
		kind = "AWS SecretsManager"
		endpoint = []string{kms.Endpoint()}
	case *gemalto.Store:
		kind = "Gemalto KeySecure"
		endpoint = []string{kms.Endpoint()}
	case *gcp.Store:
		kind = "GCP SecretManager"
		endpoint = []string{"Project: " + kms.Endpoint()}
	case *azure.Store:
		kind = "Azure KeyVault"
		endpoint = []string{kms.Endpoint()}
	case *entrust.KeyControl:
		kind = "Entrust KeyControl"
		endpoint = []string{kms.Endpoint()}
	default:
		return "", nil, fmt.Errorf("unknown KMS backend %T", kms)
	}
	return kind, endpoint, nil
}

func connectEdgeServer(ctx context.Context, filename, addr string) (edge.KeyStore, *edge.Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	store, config, err := edgeconf.Connect(ctx, file)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// Set config defaults
	const DefaultAddr = "0.0.0.0:7373"
	if addr != "" {
		config.Addr = addr
	}
	if config.Addr == "" {
		config.Addr = DefaultAddr
	}
	if config.Cache.Expiry == 0 {
		config.Cache.Expiry = 5 * time.Minute
	}
	if config.Cache.ExpiryUnused == 0 {
		config.Cache.ExpiryUnused = 30 * time.Second
	}

	if config.Admin.IsUnknown() {
		return nil, nil, errors.New("no admin identity specified")
	}
	return store, config, nil
}

func gatewayMessage(store edge.KeyStore, config *edge.Config, mlock bool) (*cli.Buffer, error) {
	ip, port := serverAddr(config.Addr)
	ifaceIPs := listeningOnV4(ip)
	if len(ifaceIPs) == 0 {
		return nil, errors.New("failed to listen on network interfaces")
	}
	kmsKind, kmsEndpoints, err := description(store)
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
