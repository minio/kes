// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"time"

	"aead.dev/mem"
	"aead.dev/minisign"
	"github.com/minio/kes/internal/cli"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/sys"
	"github.com/minio/selfupdate"
	flag "github.com/spf13/pflag"
)

const updateCmdUsage = `Usage:
    kes update [options] [<version>]

Options:
    -k, --insecure           Skip TLS certificate validation.
    -d, --downgrade          Allow downgrading to a previous version.
    -o, --output <file>      Save new binary to a file instead of
                             replacing the current binary.
        --os <OS>            Download a binary for the specified OS.
        --arch <arch>        Download a binary for the specified CPU
                             architecture.
        --minisign-key <key> Use the specified minisign public key to
                             verify the binary signature.
    -h, --help               Print command line options.

Examples:
    $ kes update
    $ kes update v0.21.0
    $ kes update -o ./kes-darwin-arm64 --os darwin --arch arm64
`

const defaultMinisignKey = "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"

func updateCmd(args []string) {
	cmd := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cmd.Usage = func() { fmt.Fprint(os.Stderr, updateCmdUsage) }

	var (
		insecureSkipVerify bool
		downgrade          bool
		outputFile         string
		osFlag             string
		archFlag           string
		minisignKey        string
	)
	cmd.BoolVarP(&insecureSkipVerify, "insecure", "k", false, "Skip TLS certificate validation")
	cmd.BoolVarP(&downgrade, "downgrade", "d", false, "Allow downgrading to a previous version")
	cmd.StringVarP(&outputFile, "output", "o", "", "Save new binary to a file instead of replacing the current binary")
	cmd.StringVar(&osFlag, "os", runtime.GOOS, "Download a binary for the specified OS")
	cmd.StringVar(&archFlag, "arch", runtime.GOARCH, "Download a binary for the specified CPU architecture")
	cmd.StringVar(&minisignKey, "minisign-key", defaultMinisignKey, "Use the specified minisign public key to verify the binary signature")
	if err := cmd.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		cli.Fatalf("%v. See 'kes update --help'", err)
	}
	if cmd.NArg() > 1 {
		cli.Fatal("too many arguments. See 'kes update --help'")
	}
	if osFlag != runtime.GOOS && outputFile == "" {
		cli.Fatalf("cannot update to a '%s' binary on %s-%s. Use '--output'", osFlag, runtime.GOOS, runtime.GOARCH)
	}
	if archFlag != runtime.GOARCH && outputFile == "" {
		cli.Fatalf("cannot update to a '%s' binary on %s-%s. Use '--output'", archFlag, runtime.GOOS, runtime.GOARCH)
	}

	const (
		Latest      = "latest"
		DownloadURL = "https://github.com/minio/kes/releases/download/%s/kes-%s-%s"
	)
	var publicKey minisign.PublicKey
	if err := publicKey.UnmarshalText([]byte(minisignKey)); err != nil {
		cli.Fatalf("failed to parse public key: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	client := xhttp.Retry{
		N: 2,
		Client: http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecureSkipVerify,
				},
			},
		},
	}

	releaseTagFormat := "2006-01-02T15-04-05Z"
	// First, we check what's the latest version and do some
	// version comparison - i.e. are we already running the
	// latest version, are we downgrading, etc.
	var version time.Time
	if n := cmd.NArg(); n == 0 || n == 1 && cmd.Arg(0) == Latest {
		const (
			MaxBody   = 5 * mem.MiB
			LatestURL = "https://api.github.com/repos/minio/kes/releases/latest"
			Tag       = "tag_name"
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, LatestURL, nil)
		if err != nil {
			cli.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			cli.Fatalf("failed to download KES release information: %v", err)
		}
		defer xhttp.DrainBody(resp.Body)

		var response map[string]any
		if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxBody)).Decode(&response); err != nil {
			cli.Fatalf("failed to download KES release information: %v", err)
		}
		tag, ok := response[Tag].(string)
		if !ok {
			cli.Fatalf("failed to download KES release information: invalid release tag '%v", response[Tag])
		}
		version, err = time.Parse(releaseTagFormat, tag)
		if err != nil {
			cli.Fatalf("failed to parse KES release information: invalid release tag '%s': %v", tag, err)
		}
	} else {
		v, err := time.Parse(releaseTagFormat, cmd.Arg(0))
		if err != nil {
			cli.Fatalf("invalid release version '%s': %v", cmd.Arg(0), err)
		}
		version = v
	}

	info, _ := sys.ReadBinaryInfo()
	if cv, err := time.Parse(releaseTagFormat, info.Version); err == nil {
		switch version.After(cv) {
		case true:
			cli.Println(fmt.Sprintf("Upgrading from '%v' to '%v'", cv, version))
		case false:
			if !downgrade {
				cli.Println(fmt.Sprintf("Already on latest version %v", cv.Format(releaseTagFormat)))
				return
			}
			cli.Println(fmt.Sprintf("Downgrading from '%v' to '%v'", cv, version))
		}
	}

	// We have to download the KES binary and the corresponding minisign signature
	// file. We start with the signature.
	binaryURL, err := url.JoinPath(
		"https://github.com/minio/kes/releases/download/",
		fmt.Sprintf("v%v", version),
		fmt.Sprintf("kes-%s-%s", osFlag, archFlag),
	)
	if err != nil {
		cli.Fatalf("failed to download minisign signature: %v", err)
	}

	cli.Print("Downloading KES minisign signature...")
	startTime := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL+".minisig", nil)
	if err != nil {
		cli.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		cli.Fatalf("failed to download minisign signature: %v", err)
	}
	defer xhttp.DrainBody(resp.Body)

	bytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(1*mem.MB)))
	if err != nil {
		cli.Fatalf("failed to download minisign signature: %v", err)
	}
	var signature minisign.Signature
	if err = signature.UnmarshalText(bytes); err != nil {
		cli.Fatal(err)
	}
	cli.Println(fmt.Sprintf("\033[2K\rDownloaded KES minisign signature in %0.1f seconds", time.Since(startTime).Seconds()))

	// Now download the actual KES binary.
	cli.Print("Downloading KES binary ...")
	startTime = time.Now()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		cli.Fatalf("failed to download binary: %v", err)
	}
	resp, err = client.Do(req)
	if err != nil {
		cli.Fatalf("failed to download binary: %v", err)
	}
	defer xhttp.DrainBody(resp.Body)

	// If the outputFile does not exist we create an empty
	// one such that selfupdate can do a successful rename
	// later on.
	// Otherwise, the selfupdate binary swap (via rename)
	// fails since the "original" file does not exist.
	if outputFile != "" {
		_, err = os.Stat(outputFile)
		if errors.Is(err, os.ErrNotExist) {
			if err = os.WriteFile(outputFile, nil, 0o755); err != nil {
				cli.Fatal(err)
			}
		}
		if err != nil {
			cli.Fatal(err)
		}
	}

	totalSize := mem.Size(resp.ContentLength)
	verifier := &minisignVerifier{
		src:       minisign.NewReader(resp.Body),
		key:       publicKey,
		signature: bytes,
	}
	progress := mem.NewProgressReader(verifier, 500*time.Millisecond, func(p mem.Progress) {
		fmt.Print("\033[2K\r")
		if !p.Done() {
			fmt.Printf(
				"Downloading KES binary %s/%s  (%s/s)",
				mem.FormatSize(p.Total, 'D', 2),
				mem.FormatSize(totalSize, 'D', 2),
				mem.FormatSize(2*p.N, 'D', 2),
			)
		}
	})

	if err = selfupdate.Apply(progress, selfupdate.Options{TargetPath: outputFile}); err != nil {
		if err = selfupdate.RollbackError(err); err != nil {
			cli.Fatalf("failed to download binary: %v", err)
		}
		cli.Fatalf("failed to download binary: %v", err)
	}
	cli.Println(fmt.Sprintf("Downloaded KES binary in %0.1f seconds", time.Since(startTime).Seconds()))
	cli.Println()
	cli.Println(fmt.Sprintf("Updated to KES v%v", version))
}

type minisignVerifier struct {
	src       *minisign.Reader
	key       minisign.PublicKey
	signature []byte
}

func (r *minisignVerifier) Read(b []byte) (int, error) {
	n, err := r.src.Read(b)
	if errors.Is(err, io.EOF) {
		if !r.src.Verify(r.key, r.signature) {
			return 0, errors.New("kes: minisign signature verification failed")
		}
	}
	return n, err
}
