// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/minio/selfupdate"
)

func getUpdateTransport(timeout time.Duration) http.RoundTripper {
	var updateTransport http.RoundTripper = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: timeout,
			DualStack: true,
		}).DialContext,
		IdleConnTimeout:       timeout,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: timeout,
		DisableCompression:    true,
	}
	return updateTransport
}

func getUpdateReaderFromURL(u string, transport http.RoundTripper) (io.ReadCloser, int64, error) {
	clnt := &http.Client{
		Transport: transport,
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, -1, err
	}

	resp, err := clnt.Do(req)
	if err != nil {
		return nil, -1, err
	}
	return resp.Body, resp.ContentLength, nil
}

const defaultPubKey = "RWTx5Zr1tiHQLwG9keckT0c45M3AGeHD6IvimQHpyRywVWGbP1aVSGav"

func getLatestRelease(tr http.RoundTripper) (string, error) {
	releaseURL := "https://api.github.com/repos/minio/kes/releases/latest"

	body, _, err := getUpdateReaderFromURL(releaseURL, tr)
	if err != nil {
		return "", fmt.Errorf("unable to access github release URL %w", err)
	}
	defer body.Close()

	lm := make(map[string]interface{})
	if err = json.NewDecoder(body).Decode(&lm); err != nil {
		return "", err
	}
	rel, ok := lm["tag_name"].(string)
	if !ok {
		return "", errors.New("unable to find latest release tag")
	}
	return rel, nil
}

func updateInplace() error {
	transport := getUpdateTransport(30 * time.Second)
	rel, err := getLatestRelease(transport)
	if err != nil {
		return err
	}

	kesBin := fmt.Sprintf("https://github.com/minio/kes/releases/download/%s/kes-%s-%s", rel, runtime.GOOS, runtime.GOARCH)
	reader, length, err := getUpdateReaderFromURL(kesBin, transport)
	if err != nil {
		return fmt.Errorf("unable to fetch binary from %s: %w", kesBin, err)
	}

	minisignPubkey := os.Getenv("KES_MINISIGN_PUBKEY")
	if minisignPubkey == "" {
		minisignPubkey = defaultPubKey
	}

	v := selfupdate.NewVerifier()
	if err = v.LoadFromURL(kesBin+".minisig", minisignPubkey, transport); err != nil {
		return fmt.Errorf("unable to fetch binary signature for %s: %w", kesBin, err)
	}
	opts := selfupdate.Options{
		Verifier: v,
	}

	tmpl := `{{ red "Downloading:" }} {{bar . (red "[") (green "=") (red "]")}} {{speed . | rndcolor }}`
	bar := pb.ProgressBarTemplate(tmpl).Start64(length)
	barReader := bar.NewProxyReader(reader)
	if err = selfupdate.Apply(barReader, opts); err != nil {
		bar.Finish()
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			return rerr
		}
		return err
	}

	bar.Finish()
	fmt.Printf("Updated 'kes' to latest release %s\n", rel)
	return nil
}
