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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/kes"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
)

// Store is a generic KeyStore that stores/fetches keys from a
// v1 KeyStore plugin compatible service.
type Store struct {
	Endpoint string // Endpoint of the KeyStore plugin / generic KeyStore.

	KeyPath  string // Path to the TLS client private key.
	CertPath string // Path to the TLS client certificate.
	CAPath   string // Path to one (or directory of) root CA certificates.

	// ErrorLog specifies an optional logger for errors.
	// If an unexpected error is encountered while trying
	// to fetch, store or delete a key or when an authentication
	// error happens then an error event is written to the error
	// log.
	//
	// If nil, logging is done via the log package's standard
	// logger.
	ErrorLog *log.Logger

	client xhttp.Retry
}

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Create creates the given key-value pair at the generic KeyStore if
// and only if the given key does not exist. If such an entry already
// exists it returns kes.ErrKeyExists.
func (s *Store) Create(ctx context.Context, name string, key key.Key) error {
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	body, err := json.Marshal(Request{
		Bytes: []byte(key.String()),
	})
	if err != nil {
		s.logf("generic: failed to create key %q: %v", name, err)
		return errCreateKey
	}

	url := endpoint(s.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		s.logf("generic: failed to create key %q: %v", name, err)
		return errCreateKey
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logf("generic: failed to create key %q: %v", name, err)
		}
		return errCreateKey
	}
	if resp.StatusCode != http.StatusCreated {
		switch err = parseErrorResponse(resp); {
		case err == kes.ErrKeyExists:
			return kes.ErrKeyExists
		default:
			s.logf("generic: failed to create key %q: %v", name, err)
			return errCreateKey
		}
	}
	return nil
}

// Delete removes a the value associated with the given key
// from the generic KeyStore, if it exists.
func (s *Store) Delete(ctx context.Context, name string) error {
	url := endpoint(s.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		s.logf("generic: failed to delete key %q: %v", name, err)
		return errDeleteKey
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logf("generic: failed to delete key %q: %v", name, err)
		}
		return errDeleteKey
	}
	if resp.StatusCode != http.StatusOK {
		if err = parseErrorResponse(resp); err != nil {
			s.logf("generic: failed to delete key %q: %v", name, err)
		}
		return errDeleteKey
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, name string) (key.Key, error) {
	type Response struct {
		Bytes []byte `json:"bytes"`
	}

	url := endpoint(s.Endpoint, "/v1/key", url.PathEscape(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.logf("generic: failed to access key %q: %v", name, err)
		return key.Key{}, errGetKey
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logf("generic: failed to access key %q: %v", name, err)
		}
		return key.Key{}, errGetKey
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch err = parseErrorResponse(resp); {
		case err == kes.ErrKeyNotFound:
			return key.Key{}, kes.ErrKeyNotFound
		default:
			s.logf("generic: failed to access key %q: %v", name, err)
			return key.Key{}, errGetKey
		}
	}

	var (
		decoder  = json.NewDecoder(io.LimitReader(resp.Body, key.MaxSize))
		response Response
	)
	if err = decoder.Decode(&response); err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logf("generic: failed to parse server response: %v", err)
		}
		return key.Key{}, errGetKey
	}

	k, err := key.Parse(string(response.Bytes))
	if err != nil {
		s.logf("generic: failed to parse key %q: %v", name, err)
		return key.Key{}, err
	}
	return k, nil
}

// List returns a new Iterator over the names of all stored keys.
func (s *Store) List(ctx context.Context) (key.Iterator, error) {
	url := endpoint(s.Endpoint, "/v1/key")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.logf("generic: failed to list keys: %v", err)
		return nil, errListKey
	}
	resp, err := s.client.Do(req)
	if err != nil {
		s.logf("generic: failed to list keys: %v", err)
		return nil, errListKey
	}
	if resp.StatusCode != http.StatusOK {
		if err = parseErrorResponse(resp); err != nil {
			s.logf("generic: failed to list keys: %v", err)
		}
		return nil, errListKey
	}

	decoder := json.NewDecoder(resp.Body)
	return &iterator{
		response: resp,
		decoder:  decoder,
	}, nil
}

func (s *Store) Authenticate() error {
	var config = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if s.CertPath != "" || s.KeyPath != "" {
		certificate, err := tls.LoadX509KeyPair(s.CertPath, s.KeyPath)
		if err != nil {
			return err
		}
		config.Certificates = append(config.Certificates, certificate)
	}
	if s.CAPath != "" {
		rootCAs, err := loadCustomCAs(s.CAPath)
		if err != nil {
			return err
		}
		config.RootCAs = rootCAs
	}
	s.client = xhttp.Retry{
		Client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: config,
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
	}
	return nil
}

type keyDescription struct {
	Name string `json:"name"`
	Last bool   `json:"last"`
}

type iterator struct {
	response *http.Response
	decoder  *json.Decoder

	last   keyDescription
	err    error
	closed bool
}

func (i *iterator) Next() bool {
	if i.closed || i.err != nil {
		return false
	}
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
	}
	return true
}

func (i *iterator) Name() string {
	return i.last.Name
}

func (i *iterator) Err() error { return i.err }

func (i *iterator) Close() error {
	i.closed = true
	return i.response.Body.Close()
}

// endpoint returns an endpoint URL starting with the
// given endpoint followed by the path elements.
//
// For example:
//   • endpoint("https://127.0.0.1:7373", "version")                => "https://127.0.0.1:7373/version"
//   • endpoint("https://127.0.0.1:7373/", "/key/create", "my-key") => "https://127.0.0.1:7373/key/create/my-key"
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

	const MaxBodySize = 1 << 20
	var size = resp.ContentLength
	if size < 0 || size > MaxBodySize {
		size = MaxBodySize
	}

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") {
		type Response struct {
			Message string `json:"message"`
		}
		var response Response
		if err := json.NewDecoder(io.LimitReader(resp.Body, size)).Decode(&response); err != nil {
			return err
		}
		return kes.NewError(resp.StatusCode, response.Message)
	}

	var sb strings.Builder
	if _, err := io.Copy(&sb, io.LimitReader(resp.Body, size)); err != nil {
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
	var rootCAs = x509.NewCertPool()

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

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, v...)
	} else {
		log.Printf(format, v...)
	}
}
