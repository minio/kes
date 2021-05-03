// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package gemalto implements a key store that fetches/stores
// cryptographic keys on a Gemalto KeySecure instance.
package gemalto

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/minio/kes"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/secret"
)

// Credentials represents a Gemalto KeySecure
// refresh token that can be used to obtain a
// short-lived authentication token.
//
// A token is valid within either the default root
// domain (empty) or a specifc domain - e.g. my-domain.
type Credentials struct {
	Token  string        // The KeySecure refresh token
	Domain string        // The KeySecure domain - similar to a Vault Namespace
	Retry  time.Duration // The time to wait before trying to re-authenticate
}

// KeySecure is a Gemalto KeySecure client that
// stores / fetches key-value pairs as secrets.
//
// It tries to connect to a KeySecure instance
// at the given endpoint and uses the login
// credentials to authenticate.
type KeySecure struct {
	// Endpoint is the KeySecure instance endpoint.
	Endpoint string

	// CAPath is a path to the root CA certificate(s)
	// used to verify the TLS certificate of the KeySecure
	// instance. If empty, the host's root CA set is used.
	CAPath string

	// Login credentials are used to authenticate to the
	// KeySecure instance and obtain a short-lived authentication
	// token.
	Login Credentials

	// ErrorLog specifies an optional logger for errors.
	// If an unexpected error is encountered while trying
	// to fetch, store or delete a key or when an authentication
	// error happens then an error event is written to the error
	// log.
	//
	// If nil, logging is done via the log package's standard
	// logger.
	ErrorLog *log.Logger

	client *client
}

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Authenticate tries to establish a connection to a
// KeySecure server using the login credentials.
//
// It retruns an error if no connection could be
// established - for instance because of invalid
// credentials.
func (s *KeySecure) Authenticate() (err error) {
	var rootCAs *x509.CertPool
	if s.CAPath != "" {
		rootCAs, err = loadCustomCAs(s.CAPath)
		if err != nil {
			return err
		}
	}

	s.client = &client{
		ErrorLog: s.ErrorLog,
		Retry: xhttp.Retry{
			Client: http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: rootCAs,
					},
					Proxy: http.ProxyFromEnvironment,
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
	}
	if err = s.client.Authenticate(s.Endpoint, s.Login); err != nil {
		return err
	}
	go s.client.RenewAuthToken(context.Background(), s.Endpoint, s.Login)
	return nil
}

// Create creates the given key-value pair at Gemalto if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *KeySecure) Create(key, value string) error {
	type Request struct {
		Type  string `json:"dataType"`
		Value string `json:"material"`
		Name  string `json:"name"`
	}

	body, err := json.Marshal(Request{
		Type:  "seed", // KeySecure supports blob, password and seed
		Value: value,
		Name:  key,
	})
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to create key %q: %v", key, err)
		return errCreateKey
	}

	url := fmt.Sprintf("%s/api/v1/vault/secrets", s.Endpoint)
	req, err := http.NewRequest(http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to create key %q: %v", key, err)
		return errCreateKey
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", s.client.AuthToken())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		if resp.StatusCode == http.StatusConflict {
			return kes.ErrKeyExists
		}
		if response, err := parseServerError(resp); err != nil {
			logf(s.ErrorLog, "gemalto: %q: failed to parse server response: %v", resp.Status, err)
		} else {
			logf(s.ErrorLog, "gemalto: failed to create key %q: %q (%d)", key, response.Message, response.Code)
		}
		return errCreateKey
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *KeySecure) Get(key string) (string, error) {
	type Response struct {
		Value string `json:"material"`
	}

	url := fmt.Sprintf("%s/api/v1/vault/secrets/%s/export?type=name", s.Endpoint, key)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to access key %q: %v", key, err)
		return "", errGetKey
	}
	req.Header.Set("Authorization", s.client.AuthToken())

	resp, err := s.client.Do(req)
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to access key %q: %v", key, err)
		return "", errGetKey
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", kes.ErrKeyNotFound
		}
		if response, err := parseServerError(resp); err != nil {
			logf(s.ErrorLog, "gemalto: %q: failed to parse server response: %v", resp.Status, err)
		} else {
			logf(s.ErrorLog, "gemalto: failed to access key %q: %q (%d)", key, response.Message, response.Code)
		}
		return "", errGetKey
	}

	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&response); err != nil {
		logf(s.ErrorLog, "gemalto: failed to parse server response: %v", err)
		return "", errGetKey
	}
	return response.Value, nil
}

// Delete removes a the value associated with the given key
// from Gemalto, if it exists.
func (s *KeySecure) Delete(key string) error {
	url := fmt.Sprintf("%s/api/v1/vault/secrets/%s?type=name", s.Endpoint, key)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to delete key %q: %v", key, err)
		return errDeleteKey
	}
	req.Header.Set("Authorization", s.client.AuthToken())

	resp, err := s.client.Do(req)
	if err != nil {
		logf(s.ErrorLog, "gemalto: failed to delete key %q: %v", key, err)
		return errDeleteKey
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		// BUG(aead): The KeySecure server returns 404 NotFound if the
		// secret does not exist but also when we are not allowed to access/delete
		// the secret due to insufficient policy permissions.
		// The reason for this is probably that a client should not be able
		// to determine whether a particular secret exists (if the client has
		// no access to it).
		// Unfortunately, we cannot guarantee anymore that we actually deleted the
		// secret. It could also be the case that we lost access (e.g. due to a
		// policy change). So, in this case we don't return an error such that the
		// client thinks it has deleted the secret successfully.
		if response, err := parseServerError(resp); err != nil {
			logf(s.ErrorLog, "gemalto: %s: failed to parse server response: %v", resp.Status, err)
		} else {
			logf(s.ErrorLog, "gemalto: failed to delete key '%s': %s (%d)", key, response.Message, response.Code)
		}
		return errDeleteKey
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *KeySecure) List(ctx context.Context) (secret.Iterator, error) {
	// Response is the JSON response returned by KeySecure.
	// It only contains the fields that we need to implement
	// paginated listing. The raw response contains much more
	// information - like created-at date etc.
	type Response struct {
		Skip      uint64 `json:"skip"`  // The number of items skipped (in total)
		Total     uint64 `json:"total"` // The total number of items
		Resources []struct {
			Name string `json:"name"` // The name of the key
		} `json:"resources"`
	}

	values := make(chan string, 10)
	iterator := &iterator{
		values: values,
	}

	// The following go-routine keeps listing keys (in pages of size 'limit')
	// and writes the keys names to the Iterator.
	// If there are so many items such that they don't fit on a single page it
	// requests another page by making another request and skipping all items
	// processed so far.
	go func() {
		defer close(values)

		const limit = 200 // We limit a listing page to 200. This an arbitrary but reasonable value.
		var (
			skip     uint64 // Keep track of the items processed so far and skip them.
			response Response
		)
		for {
			// We have to tell KeySecure how many items we want to process per page and how many
			// items we want to skip - resp. how many items we have processed already.
			url := fmt.Sprintf("%s/api/v1/vault/secrets?limit=%d&skip=%d", s.Endpoint, limit, skip)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				logf(s.ErrorLog, "gemalto: failed to list keys: %v", err)
				iterator.SetErr(errListKey)
				break
			}
			req.Header.Set("Authorization", s.client.AuthToken())

			resp, err := s.client.Do(req)
			if err != nil {
				if err == context.Canceled {
					break // We stop once the request got canceled
				}
				logf(s.ErrorLog, "gemalto: failed to list keys: %q", err)
				iterator.SetErr(errListKey)
				break
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				if response, err := parseServerError(resp); err != nil {
					logf(s.ErrorLog, "gemalto: %q: failed to parse server response: %v", resp.Status, err)
				} else {
					logf(s.ErrorLog, "gemalto: failed to list keys: %q (%d)", response.Message, response.Code)
				}
				iterator.SetErr(err)
				break
			}

			const MaxBody = 32 * (1 << 20) // A page should not be larger than 32 MiB.
			if err := json.NewDecoder(io.LimitReader(resp.Body, MaxBody)).Decode(&response); err != nil {
				if err == context.Canceled {
					break // We stop once the request got canceled
				}
				logf(s.ErrorLog, "gemalto: failed to list keys: listing page too large: %q", err)
				iterator.SetErr(errListKey)
				break
			}

			// We check that the invariant that the KeySecure instance has skipped as many items
			// as we requested is true. If both numbers are off then the KeySecure would either
			// return items that we've already served to the client or skip items that we haven't
			// served, yet.
			if response.Skip != skip {
				logf(s.ErrorLog, "gemalto: failed to list keys: pagination is out-of-sync: tried to skip %d but skipped %d", skip, response.Skip)
				iterator.SetErr(errListKey)
				break
			}
			for _, v := range response.Resources {
				values <- v.Name
			}

			skip += uint64(len(response.Resources))
			if response.Skip >= response.Total { // Stop once we've reached the end of the listing.
				break
			}
		}
	}()
	return iterator, nil
}

type iterator struct {
	values <-chan string
	last   string

	lock sync.Mutex
	err  error
}

func (i *iterator) Next() bool {
	v, ok := <-i.values
	if !ok {
		return false
	}
	i.last = v
	return true
}

func (i *iterator) Value() string { return i.last }

func (i *iterator) Err() error {
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.err
}

func (i *iterator) SetErr(err error) {
	i.lock.Lock()
	i.err = err
	i.lock.Unlock()
}

// errResponse represents a KeySecure API error
// response.
type errResponse struct {
	Code    int    `json:"code"`
	Message string `json:"codeDesc"`
}

func parseServerError(resp *http.Response) (errResponse, error) {
	const MaxSize = 1 << 20 // max. 1 MiB
	var size = resp.ContentLength
	if size < 0 || size > MaxSize {
		size = MaxSize
	}
	defer resp.Body.Close()

	// The KeySecure server does not always return a JSON error
	// response bodies. It only returns a JSON body in case
	// of a well-defined API error - e.g. when trying to create
	// a secret with a name that already exists.
	// It does not return a JSON body in case of a missing
	// authorization header.
	// Therefore, we try to unmarshal the body only when the
	// Content-Type is application/json. Otherwise, we just assume
	// the body is a raw text string and use the HTTP response code
	// as error code.

	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/json") {
		var response errResponse
		err := json.NewDecoder(io.LimitReader(resp.Body, size)).Decode(&response)
		return response, err
	}

	var s strings.Builder
	if _, err := io.Copy(&s, io.LimitReader(resp.Body, size)); err != nil {
		return errResponse{}, err
	}
	message := strings.TrimSpace(s.String())
	if strings.HasSuffix(message, "\n") { // Some error message end with '\n' causing messy logs
		message = strings.TrimSuffix(message, "\n")
	}
	return errResponse{
		Code:    resp.StatusCode,
		Message: message,
	}, nil
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

func logf(logger *log.Logger, format string, v ...interface{}) {
	if logger == nil {
		log.Printf(format, v...)
	} else {
		logger.Printf(format, v...)
	}
}
