// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const module = `github.com/minio/kes`

const help = `%s [options] [tag]

  --proxy              The Go proxy endpoint. (default: $GOPROXY)

  -h, --help           Show list of command-line options. 
`

func main() {
	var proxy string
	flag.StringVar(&proxy, "proxy", os.Getenv("GOPROXY"), "The Go proxy endpoint")
	flag.Usage = func() {
		fmt.Printf(help, flag.CommandLine.Name())
	}
	flag.Parse()

	var tag = "latest"
	if args := flag.Args(); len(args) > 0 {
		if len(args) > 1 {
			fmt.Fprintln(os.Stderr, "unknown argument", args[1])
			os.Exit(1)
		}
		tag = args[0]
	}

	var proxies []string
	for i, p := range strings.Split(proxy, ",") {
		if p == "" || p == "direct" || p == "off" {
			continue
		}

		if _, err := url.Parse(p); err != nil {
			fmt.Fprintf(os.Stderr, "%d-th proxy is not a valid URL: %v\n", i, err)
			os.Exit(1)
		}
		proxies = append(proxies, p)
	}
	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "no Go proxy specified")
		os.Exit(1)
	}

	// If we fetch the latest release version we try
	// $GOPROXY/<module>/@latest first. However, we
	// don't abort if this fails since the @latest
	// API is optional for a Go proxy implementation.
	// See: go help goproxy
	if tag == "latest" {
		version, err := getLatestVersion(proxies[0])
		if err == nil {
			fmt.Println(version)
			return
		}
	}

	// Now, fetch all available release versions using
	// $GOPROXY/<module>/@v/list. The proxy returns the
	// list in an arbitrary order. Therefore we sort it
	// first and then get the last (== latest for sem-ver)
	// version entry.
	versions, err := listVersions(proxies[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to list versions for %s from %s: %v\n", module, proxies[0], err)
		os.Exit(1)
	}
	if tag == "latest" {
		sort.Strings(versions)
		fmt.Println(versions[len(versions)-1])
		return
	}

	for _, version := range versions {
		if version == tag {
			fmt.Println(version)
			return
		}
	}
	fmt.Fprintf(os.Stderr, "version %s does not exist\n", tag)
	os.Exit(1)
}

// getLatestVersion tries to fetch the latest version
// form the given Go proxy.
func getLatestVersion(proxy string) (string, error) {
	resp, err := http.Get(fmt.Sprintf(`%s/%s/%s`, proxy, module, "@latest"))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	decoder.DisallowUnknownFields()

	type Version struct {
		Version string    `json:"version"`
		Time    time.Time `json:"time"`
	}
	var version Version
	if err = decoder.Decode(&version); err != nil {
		return "", err
	}
	if version.Version == "" {
		return "", errors.New("Go proxy returned empty version as latest")
	}
	return version.Version, nil
}

// listVersions tries to fetch all versions from the
// given Go proxy. It expects all versions to be of
// the form:
//  v<major>.<minor>.<patch> (semantic versioning)
func listVersions(proxy string) ([]string, error) {
	resp, err := http.Get(fmt.Sprintf(`%s/%s/%s`, proxy, module, `@v/list`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	var versions []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for scanner.Scan() {
		version := scanner.Text()
		if !strings.HasPrefix(version, "v") {
			continue
		}

		numbers := strings.SplitN(strings.TrimPrefix(version, "v"), ".", 3)
		if n, err := strconv.Atoi(numbers[0]); n < 0 || err != nil { // major
			continue
		}
		if n, err := strconv.Atoi(numbers[1]); n < 0 || err != nil { // minor
			continue
		}
		if n, err := strconv.Atoi(numbers[2]); n < 0 || err != nil { // patch
			continue
		}

		versions = append(versions, version)
	}
	if err = scanner.Err(); err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, errors.New("no versions received")
	}
	return versions, err
}
