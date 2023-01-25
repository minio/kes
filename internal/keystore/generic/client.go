// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package generic

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/kms"
)

// Config is a structure containing
// all generic KMS plugin configuration.
type Config struct {
	// Endpoint is the endpoint of the
	// KMS plugin.
	Endpoint string

	// PrivateKey is an optional path to a
	// TLS private key file containing a
	// TLS private key for mTLS authentication.
	PrivateKey string

	// Certificate is an optional path to a
	// TLS certificate file containing a
	// TLS certificate for mTLS authentication.
	Certificate string

	// CAPath is an optional path to the root
	// CA certificate(s) for verifying the TLS
	// certificate of the KMS plugin. If empty,
	// the OS default root CA set is used.
	CAPath string
}

// Conn is a connection to a generic KMS plugin.
type Conn struct {
	config Config
	client xhttp.Retry
}

// Connect connects to the KMS plugin using the
// given configuration.
func Connect(ctx context.Context, config *Config) (*Conn, error) {
	if config == nil || config.Endpoint == "" {
		return nil, errors.New("generic: endpoint is empty")
	}
	_, err := kms.Dial(ctx, config.Endpoint)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if config.Certificate != "" || config.PrivateKey != "" {
		certificate, err := tls.LoadX509KeyPair(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
	}
	if config.CAPath != "" {
		rootCAs, err := loadCustomCAs(config.CAPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = rootCAs
	}
	return &Conn{
		config: *config,
		client: xhttp.Retry{
			Client: http.Client{
				Transport: &http.Transport{
					TLSClientConfig: tlsConfig,
					Proxy:           http.ProxyFromEnvironment,
					DialContext: (&net.Dialer{
						Timeout:   10 * time.Second,
						KeepAlive: 10 * time.Second,
						DualStack: true,
					}).DialContext,
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       30 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				},
			},
		},
	}, nil
}

var _ kms.Conn = (*Conn)(nil)

// Status returns the current state of the generic KeyStore instance.
// In particular, whether it is reachable and the network latency.
func (c *Conn) Status(ctx context.Context) (kms.State, error) {
	return kms.Dial(ctx, c.config.Endpoint)
}

// Create creates the given key-value pair at the generic KeyStore if
// and only if the given key does not exist. If such an entry already
// exists it returns kes.ErrKeyExists.
func (c *Conn) Create(ctx context.Context, name string, value []byte) error {
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	body, err := json.Marshal(Request{
		Bytes: value,
	})
	if err != nil {
		return fmt.Errorf("generic: failed to create key '%s': %v", name, err)
	}

	url := endpoint(c.config.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return fmt.Errorf("generic: failed to create key '%s': %v", name, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("generic: failed to create key '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusCreated {
		switch err = parseErrorResponse(resp); {
		case err == kes.ErrKeyExists:
			return kes.ErrKeyExists
		default:
			return fmt.Errorf("generic: failed to create key '%s': %v", name, err)
		}
	}
	return nil
}

// Delete removes a the value associated with the given key
// from the generic KeyStore, if it exists.
func (c *Conn) Delete(ctx context.Context, name string) error {
	url := endpoint(c.config.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("generic: failed to delete key '%s': %v", name, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("generic: failed to delete key '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		if err = parseErrorResponse(resp); err != nil {
			return fmt.Errorf("generic: failed to delete key '%s': %v", name, err)
		}
		return fmt.Errorf("generic: failed to delete key '%s': %s (%d)", name, http.StatusText(resp.StatusCode), resp.StatusCode)
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (c *Conn) Get(ctx context.Context, name string) ([]byte, error) {
	type Response struct {
		Bytes []byte `json:"bytes"`
	}

	url := endpoint(c.config.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("generic: failed to access key '%s': %v", name, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("generic: failed to access key '%s': %v", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch err = parseErrorResponse(resp); {
		case err == kes.ErrKeyNotFound:
			return nil, kes.ErrKeyNotFound
		case err == nil:
			return nil, fmt.Errorf("generic: failed to access key '%s': %s (%d)", name, http.StatusText(resp.StatusCode), resp.StatusCode)
		default:
			return nil, fmt.Errorf("generic: failed to access key '%s': %v", name, err)
		}
	}

	var (
		decoder  = json.NewDecoder(mem.LimitReader(resp.Body, key.MaxSize))
		response Response
	)
	if err = decoder.Decode(&response); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, fmt.Errorf("generic: failed to parse server response: %v", err)
	}
	return response.Bytes, nil
}

// List returns a new Iterator over the names of all stored keys.
func (c *Conn) List(ctx context.Context) (kms.Iter, error) {
	url := endpoint(c.config.Endpoint, "/v1/key")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("generic: failed to list keys: %v", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic: failed to list keys: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if err = parseErrorResponse(resp); err != nil {
			return nil, fmt.Errorf("generic: failed to list keys: %v", err)
		}
		return nil, fmt.Errorf("generic: failed to list keys: %s (%d)", http.StatusText(resp.StatusCode), resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	return kms.FuseIter(&iterator{
		response: resp,
		decoder:  decoder,
	}), nil
}

type keyDescription struct {
	Name string `json:"name"`
	Last bool   `json:"last"`
}

type iterator struct {
	response *http.Response
	decoder  *json.Decoder

	last keyDescription
	err  error
}

func (i *iterator) Next() bool {
	if err := i.decoder.Decode(&i.last); err != nil {
		if err == io.EOF {
			i.err = i.Close()
			if i.err == nil && !i.last.Last {
				i.err = io.ErrUnexpectedEOF
			}
		} else {
			i.err = err
		}
		return false
	}
	if i.last.Last {
		i.err = i.Close()
		return i.err == nil
	}
	return true
}

func (i *iterator) Name() string { return i.last.Name }

func (i *iterator) Close() error {
	if err := i.response.Body.Close(); i.err == nil {
		i.err = err
	}
	return i.err
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   - endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   - endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
//
// Any leading or trailing whitespaces are removed from
// the endpoint before it is concatenated with the path
// elements.
//
// The path elements will not be URL-escaped.
func endpoint(endpoint string, elems ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimSuffix(endpoint, "/")

	if len(elems) > 0 && !strings.HasPrefix(elems[0], "/") {
		endpoint += "/"
	}
	return endpoint + path.Join(elems...)
}

// parseErrorResponse returns an error containing
// the response status code and response body
// as error message if the response is an error
// response - i.e. status code >= 400.
//
// If the response status code is < 400, e.g. 200 OK,
// parseErrorResponse returns nil and does not attempt
// to read or close the response body.
//
// If resp is an error response, parseErrorResponse reads
// and closes the response body.
func parseErrorResponse(resp *http.Response) error {
	if resp == nil || resp.StatusCode < 400 {
		return nil
	}
	if resp.Body == nil {
		return kes.NewError(resp.StatusCode, "")
	}
	defer resp.Body.Close()

	const MaxBodySize = 1 * mem.MiB
	size := mem.Size(resp.ContentLength)
	if size < 0 || size > MaxBodySize {
		size = MaxBodySize
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") {
		type Response struct {
			Message string `json:"message"`
		}
		var response Response
		if err := json.NewDecoder(mem.LimitReader(resp.Body, size)).Decode(&response); err != nil {
			return err
		}
		return kes.NewError(resp.StatusCode, response.Message)
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, mem.LimitReader(resp.Body, size)); err != nil {
		return err
	}
	return kes.NewError(resp.StatusCode, sb.String())
}

// loadCustomCAs returns a new RootCA certificate pool
// that contains one or multiple certificates found at
// the given path.
//
// If path is a file then loadCustomCAs tries to parse
// the file as a PEM-encoded certificate.
//
// If path is a directory then loadCustomCAs tries to
// parse any file inside path as PEM-encoded certificate.
// It returns a non-nil error if one file is not a valid
// PEM-encoded X.509 certificate.
func loadCustomCAs(path string) (*x509.CertPool, error) {
	rootCAs := x509.NewCertPool()

	f, err := os.Open(path)
	if err != nil {
		return rootCAs, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return rootCAs, err
	}
	if !stat.IsDir() {
		bytes, err := ioutil.ReadAll(f)
		if err != nil {
			return rootCAs, err
		}
		if !rootCAs.AppendCertsFromPEM(bytes) {
			return rootCAs, fmt.Errorf("'%s' does not contain a valid X.509 PEM-encoded certificate", path)
		}
		return rootCAs, nil
	}

	files, err := f.Readdir(0)
	if err != nil {
		return rootCAs, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := filepath.Join(path, file.Name())
		bytes, err := ioutil.ReadFile(name)
		if err != nil {
			return rootCAs, err
		}
		if !rootCAs.AppendCertsFromPEM(bytes) {
			return rootCAs, fmt.Errorf("'%s' does not contain a valid X.509 PEM-encoded certificate", name)
		}
	}
	return rootCAs, nil
}
