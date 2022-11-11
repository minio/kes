// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fortanix

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
	"sync"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/kms"
)

// APIKey is a Fortanix API key for authenticating to
// a Fortanix SDKMS instance.
type APIKey string

// String returns a string representation of the API key
// that can be sent to a Fortanix SDKMS as part of the
// request headers.
func (k APIKey) String() string { return "Basic " + string(k) }

// Config is a structure containing configuration
// options for connecting to a Fortanix SDKMS server.
type Config struct {
	// Endpoint is the Fortanix SDKMS instance endpoint.
	Endpoint string

	// GroupID is ID of the Fortanix SDKMS group newly created
	// keys will belong to.
	//
	// Fortanix SDKMS uses groups as collection of (security) objects.
	// Typically, applications can access some/all objects within groups
	// the application is assigned to.
	GroupID string

	// APIKey is the application's Fortanix SDKMS API key used to authenticate
	// operations. It is sent on each request as part of the request headers.
	APIKey APIKey

	// CAPath is an optional path to a CA certificate or directory
	// containing CA certificates.
	//
	// If not empty, the KeyStore will use the specified CAs to
	// verify the Fortanix SDKMS server certificate.
	CAPath string
}

// Conn is a connection to a Fortanix SDKMS server.
type Conn struct {
	config Config
	client xhttp.Retry
}

var _ kms.Conn = (*Conn)(nil) // compiler check

// Connect establishes and returns a Conn to a Fortanix SDKMS server
// using the given config.
func Connect(ctx context.Context, config *Config) (*Conn, error) {
	if config == nil {
	}
	if config.Endpoint == "" {
	}

	var tlsConfig *tls.Config
	if config.CAPath != "" {
		rootCAs, err := loadCustomCAs(config.CAPath)
		if err != nil {
			return nil, err
		}
		tlsConfig = &tls.Config{
			RootCAs: rootCAs,
		}
	}

	client := xhttp.Retry{
		Client: http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig:       tlsConfig,
			},
		},
	}

	// Check if the Fortanix SDKMS endpoint is reachable
	url := endpoint(config.Endpoint, "/sys/v1/health")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", config.APIKey.String())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusNoContent {
		if err := parseErrorResponse(resp); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("fortanix: failed to connect to '%s': %s (%d)", config.Endpoint, resp.Status, resp.StatusCode)
	}

	// Check if the authentication credentials are valid
	url = endpoint(config.Endpoint, "/sys/v1/session/auth")
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", config.APIKey.String())

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		if err := parseErrorResponse(resp); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("fortanix: failed to authenticate to '%s': %s (%d)", config.Endpoint, resp.Status, resp.StatusCode)
	}
	type Response struct {
		Token string `json:"access_token"` // Raw bearer token - clients have to set 'Authorization: Bearer <token>'
	}
	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, 1*mem.MiB)).Decode(&response); err != nil {
		return nil, fmt.Errorf("fortanix: failed to authenticate to '%s': %v", config.Endpoint, err)
	}

	// Now we revoke the session we just created to cleanup any
	// session credentials we just created. This is not strictly
	// necessary but allows Fortanix SDKMS to garbage-collect
	// unused credentials early.
	url = endpoint(config.Endpoint, "/sys/v1/session/terminate")
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+response.Token)

	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusNoContent {
		if err := parseErrorResponse(resp); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("fortanix: failed to authenticate to '%s': %s (%d)", config.Endpoint, resp.Status, resp.StatusCode)
	}
	return &Conn{
		config: *config,
		client: client,
	}, nil
}

// Status returns the current state of the Fortanix SDKMS instance.
// In particular, whether it is reachable and the network latency.
func (c *Conn) Status(ctx context.Context) (kms.State, error) {
	state, err := kms.Dial(ctx, c.config.Endpoint)
	if err != nil {
		return kms.State{}, &kms.Unreachable{Err: err}
	}
	return kms.State{
		Latency: state.Latency,
	}, nil
}

// Create stors the given key at the Fortanix SDKMS if and only
// if no entry with the given name exists.
//
// If no such entry exists, Create returns kes.ErrKeyExists.
func (c *Conn) Create(ctx context.Context, name string, value []byte) error {
	type Request struct {
		Type       string   `json:"obj_type"`
		Name       string   `json:"name"`
		GroupID    string   `json:"group_id,omitempty"`
		Operations []string `json:"key_ops"`
		Value      string   `json:"value"`
		Enabled    bool     `json:"enabled"`
	}
	const (
		Type            = "OPAQUE"
		OpExport        = "EXPORT"
		OpAppManageable = "APPMANAGEABLE"
	)

	request, err := json.Marshal(Request{
		Type:       Type,
		Name:       name,
		GroupID:    c.config.GroupID,
		Operations: []string{OpExport, OpAppManageable},
		Value:      base64.StdEncoding.EncodeToString(value), // Fortanix expects base64-encoded values and will not accept raw strings
		Enabled:    true,
	})
	if err != nil {
		return err
	}

	url := endpoint(c.config.Endpoint, "/crypto/v1/keys")
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, xhttp.RetryReader(bytes.NewReader(request)))
	if err != nil {
		return fmt.Errorf("fortanix: failed to create key '%s': %v", name, err)
	}
	req.Header.Set("Authorization", c.config.APIKey.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("fortanix: failed to create key '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusCreated {
		switch err := parseErrorResponse(resp); {
		case err == nil:
			return fmt.Errorf("fortanix: failed to create key '%s': %s (%q)", name, resp.Status, resp.StatusCode)
		case resp.StatusCode == http.StatusConflict && err.Error() == "sobject already exists":
			return kes.ErrKeyExists
		default:
			return fmt.Errorf("fortanix: failed to create key '%s': %v", name, err)
		}
	}
	return nil
}

// Delete deletes the key associated with the given name
// from the Fortanix SDKMS. It may not return an error if no
// entry for the given name exists.
func (c *Conn) Delete(ctx context.Context, name string) error {
	// In order to detele a key, we need to fetch its key ID first.
	// Fortanix SDKMS API does not provide a way to delete a key
	// using just its name.
	type Request struct {
		Name string `json:"name"`
	}
	request, err := json.Marshal(Request{
		Name: name,
	})
	if err != nil {
		return fmt.Errorf("fortanix: failed to delete '%s': %v", name, err)
	}

	url := endpoint(c.config.Endpoint, "/crypto/v1/keys/export")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(request)))
	if err != nil {
		return fmt.Errorf("fortanix: failed to delete '%s': %v", name, err)
	}
	req.Header.Set("Authorization", c.config.APIKey.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("fortanix: failed to delete '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		switch err = parseErrorResponse(resp); {
		case err == nil:
			return fmt.Errorf("fortanix: failed to delete '%s': failed fetch key metadata: %s (%d)", name, resp.Status, resp.StatusCode)
		case resp.StatusCode == http.StatusNotFound && err.Error() == "sobject does not exist":
			return kes.ErrKeyNotFound
		default:
			return fmt.Errorf("fortanix: failed to delete '%s': failed to fetch key metadata: %v", name, err)
		}
	}

	type Response struct {
		KeyID string `json:"kid"`
	}
	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, key.MaxSize)).Decode(&response); err != nil {
		return fmt.Errorf("fortanix: failed to delete '%s': failed to parse key metadata: %v", name, err)
	}

	// Now, we can delete the key using its key ID.
	url = endpoint(c.config.Endpoint, "/crypto/v1/keys", response.KeyID)
	req, err = http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.config.APIKey.String())

	resp, err = c.client.Do(req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("fortanix: failed to delete '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusNoContent {
		switch err = parseErrorResponse(resp); {
		case err == nil:
			return fmt.Errorf("fortanix: failed to delete '%s': %s (%d)", name, resp.Status, resp.StatusCode)
		default:
			return fmt.Errorf("fortanix: failed to delete '%s': %v", name, err)
		}
	}
	return nil
}

// Get returns the key associated with the given name.
//
// If there is no such entry, Get returns kes.ErrKeyNotFound.
func (c *Conn) Get(ctx context.Context, name string) ([]byte, error) {
	type Request struct {
		Name string `json:"name"`
	}
	request, err := json.Marshal(Request{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("fortanix: failed to fetch %q: %v", name, err)
	}

	url := endpoint(c.config.Endpoint, "/crypto/v1/keys/export")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(request)))
	if err != nil {
		return nil, fmt.Errorf("fortanix: failed to fetch '%s': %v", name, err)
	}
	req.Header.Set("Authorization", c.config.APIKey.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("fortanix: failed to fetch '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		switch err = parseErrorResponse(resp); {
		case err == nil:
			return nil, fmt.Errorf("fortanix: failed to fetch '%s': %s (%d)", name, resp.Status, resp.StatusCode)
		case resp.StatusCode == http.StatusNotFound && err.Error() == "sobject does not exist":
			return nil, kes.ErrKeyNotFound
		default:
			return nil, fmt.Errorf("fortanix: failed to fetch '%s': %v", name, err)
		}
	}

	type Response struct {
		Value   string `json:"value"`
		Enabled bool   `json:"enabled"`
	}
	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, key.MaxSize)).Decode(&response); err != nil {
		return nil, fmt.Errorf("fortanix: failed to fetch '%s': failed to parse server response %v", name, err)
	}
	if !response.Enabled {
		return nil, fmt.Errorf("fortanix: failed to fetch '%s': key has been disabled and cannot be used until enabled again", name)
	}
	value, err := base64.StdEncoding.DecodeString(response.Value)
	if err != nil {
		return nil, fmt.Errorf("fortanix: failed to fetch '%s': %v", name, err)
	}
	return value, nil
}

// List returns a new Iterator over the Fortanix SDKMS keys.
//
// The returned iterator may or may not reflect any
// concurrent changes to the Fortanix SDKMS instance - i.e.
// creates or deletes. Further, it does not provide any
// ordering guarantees.
func (c *Conn) List(ctx context.Context) (kms.Iter, error) {
	var (
		names = make(chan string, 10)
		iter  = &iterator{
			values: names,
		}
	)

	go func() {
		defer close(names)

		var start string
		for {
			reqURL := endpoint(c.config.Endpoint, "/crypto/v1/keys") + "?sort=name:asc&limit=100"
			if start != "" {
				reqURL += "&start=" + start
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
			if err != nil {
				iter.SetErr(fmt.Errorf("fortanix: failed to list keys: %v", err))
				return
			}
			req.Header.Set("Authorization", c.config.APIKey.String())

			resp, err := c.client.Do(req)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				iter.SetErr(err)
				return
			}
			if err != nil {
				iter.SetErr(fmt.Errorf("fortanix: failed to list keys: %v", err))
				return
			}

			type Response struct {
				Name string `json:"name"`
			}
			var keys []Response
			if err := json.NewDecoder(mem.LimitReader(resp.Body, 10*key.MaxSize)).Decode(&keys); err != nil {
				iter.SetErr(fmt.Errorf("fortanix: failed to list keys: failed to parse server response: %v", err))
				return
			}
			if len(keys) == 0 {
				return
			}
			for _, k := range keys {
				select {
				case names <- k.Name:
				case <-ctx.Done():
					iter.SetErr(context.Canceled)
					return
				}
			}
			start = url.QueryEscape(keys[len(keys)-1].Name)
		}
	}()
	return kms.FuseIter(iter), nil
}

type iterator struct {
	values <-chan string

	lock sync.RWMutex
	last string
	err  error
}

var _ kms.Iter = (*iterator)(nil)

// Next moves the iterator to the next key, if any.
// This key is available until Next is called again.
//
// It returns true if and only if there is a new key
// available. If there are no more keys or an error
// has been encountered, Next returns false.
func (i *iterator) Next() bool {
	v, ok := <-i.values
	if !ok {
		return false
	}

	i.lock.Lock()
	defer i.lock.Unlock()

	i.last = v
	return i.err == nil
}

// Name returns the name of the current key. Name
// can be called multiple times an returns the
// same value until Next is called again.
func (i *iterator) Name() string {
	i.lock.RLock()
	defer i.lock.RUnlock()
	return i.last
}

// Err returns the first error, if any, encountered
// while iterating over the set of keys.
func (i *iterator) Close() error {
	i.lock.RLock()
	defer i.lock.RUnlock()
	return i.err
}

// SetErr sets the iteration error to indicate
// that the iteration failed. Subsequent calls
// to Next will return false.
func (i *iterator) SetErr(err error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.err = err
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
	if resp.StatusCode < 400 {
		return nil
	}
	if resp.Body == nil {
		return kes.NewError(resp.StatusCode, resp.Status)
	}
	defer resp.Body.Close()

	const MaxSize = 1 * mem.MiB
	size := mem.Size(resp.ContentLength)
	if size < 0 || size > MaxSize {
		size = MaxSize
	}

	if contentType := strings.TrimSpace(resp.Header.Get("Content-Type")); strings.HasPrefix(contentType, "application/json") {
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
			return rootCAs, fmt.Errorf("%q does not contain a valid X.509 PEM-encoded certificate", path)
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
			return rootCAs, fmt.Errorf("%q does not contain a valid X.509 PEM-encoded certificate", name)
		}
	}
	return rootCAs, nil
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
