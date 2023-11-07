// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package credhub

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang/groupcache/singleflight"
	"github.com/minio/kes-go"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minio/kes/kv"
)

const (
	contentType     = "Content-Type"
	applicationJson = "application/json"
)

type Config struct {
	BaseUrl                   string // The base URL endpoint of the CredHub service.
	EnableMutualTls           bool   // If set to true, enables mutual TLS.
	ClientCertFilePath        string // Path to the client's certificate file used for mutual TLS authentication.
	ClientKeyFilePath         string // Path to the client's private key file used for mutual TLS authentication.
	ServerInsecureSkipVerify  bool   // If set to true, server's certificate will not be verified against the provided CA certificate.
	ServerCaCertFilePath      string // Path to the CA certificate file for verifying the CredHub server's certificate.
	Namespace                 string // A namespace within CredHub where credentials are stored.
	ForceBase64ValuesEncoding bool   // If set to true, forces encoding of all the values as base64 before storage.
}

type Certs struct {
	ServerCaCert  *x509.Certificate
	ClientKeyPair tls.Certificate
}

func (c *Config) Validate() (*Certs, error) {
	certs := &Certs{}
	if c.BaseUrl == "" {
		return certs, errors.New("credhub config: `BaseUrl` can't be empty")
	}
	if c.Namespace == "" {
		return certs, errors.New("credhub config: `Namespace` can't be empty")
	}
	if !c.ServerInsecureSkipVerify {
		if c.ServerCaCertFilePath == "" {
			return certs, errors.New("credhub config: `ServerCaCertFilePath` can't be empty when `ServerInsecureSkipVerify` is false")
		}
		_, sCertDerBytes, err := c.validatePemFile(c.ServerCaCertFilePath, "ServerCaCertFilePath")
		if err != nil {
			return nil, err
		}
		certs.ServerCaCert, err = x509.ParseCertificate(sCertDerBytes)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("credhub config: error parsing the certificate '%s': %v", "ServerCaCertFilePath", err))
		}
	}
	if c.EnableMutualTls {
		if c.ClientCertFilePath == "" || c.ClientKeyFilePath == "" {
			return certs, errors.New("credhub config: `ClientCertFilePath` and `ClientKeyFilePath` can't be empty when `EnableMutualTls` is true")
		}
		cCertPemBytes, cCertDerBytes, err := c.validatePemFile(c.ClientCertFilePath, "ClientCertFilePath")
		if err != nil {
			return certs, err
		}
		_, err = x509.ParseCertificate(cCertDerBytes)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("credhub config: error parsing the certificate '%s': %v", "ClientCertFilePath", err))
		}
		cKeyPemBytes, _, err := c.validatePemFile(c.ClientKeyFilePath, "ClientKeyFilePath")
		if err != nil {
			return certs, err
		}
		certs.ClientKeyPair, err = tls.X509KeyPair(cCertPemBytes, cKeyPemBytes)
		if err != nil {
			return certs, err
		}
	}
	return certs, nil
}

func (c *Config) validatePemFile(path, name string) (pemBytes, derBytes []byte, err error) {
	pemBytes, err = os.ReadFile(path)
	if err != nil {
		return pemBytes, nil, errors.New(fmt.Sprintf("credhub config: failed to load PEM file '%s'='%s': %v", name, path, err))
	}
	derBlock, _ := pem.Decode(pemBytes)
	if derBlock == nil {
		return pemBytes, nil, errors.New(fmt.Sprintf("credhub config: failed to decode the '%s'='%s' from PEM format, no PEM data found", name, path))
	}
	return pemBytes, derBlock.Bytes, nil
}

type Store struct {
	LastError error
	config    *Config
	client    HttpClient
	sfGroup   singleflight.Group
}

func NewStore(_ context.Context, config *Config) (*Store, error) {
	client, err := NewHttpMTlsClient(config)
	if err != nil {
		return nil, err
	} else {
		return &Store{config: config, client: client}, nil
	}
}

// Status returns the current state of the Store or an error explaining why fetching status information failed.
//
// CredHub "Get Server Status":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_get_server_status
// - `credhub curl -X=GET -p /health`
func (s *Store) Status(ctx context.Context) (kv.State, error) {
	uri := "/health"
	startTime := time.Now()
	resp := s.client.DoRequest(ctx, http.MethodGet, uri, nil)
	defer resp.CloseResource()
	if resp.err != nil {
		return kv.State{Latency: 0}, resp.err
	}
	state := kv.State{
		Latency: time.Since(startTime),
	}

	if resp.IsStatusCode2xx() {
		var responseData struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			return state, fmt.Errorf("failed to parse response: %v", err)
		} else {
			if responseData.Status == "UP" {
				return state, nil
			} else {
				return state, fmt.Errorf("CredHub is not UP, status: %s", responseData.Status)
			}
		}
	} else {
		return state, fmt.Errorf("the CredHub (%s) is not healthy, status: %s", uri, resp.Status)
	}
}

// Create creates a new entry at the storage if and only if no entry for the give key exists.
// If such an entry already exists, Create returns ErrExists.
//
// CredHub: there is no method to do it, implemented workaround with limitations
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	_, err := s.sfGroup.Do(s.config.Namespace+"/"+name, func() (interface{}, error) {
		_, err := s.Get(ctx, name)
		if err == nil {
			return nil, fmt.Errorf("key '%s' already exists: %w", name, kes.ErrKeyExists)
		} else if errors.Is(err, kes.ErrKeyNotFound) {
			return nil, s.put(ctx, name, value)
		} else {
			return nil, err
		}
	})
	return err
}

// Set writes the key-value pair to the storage.
// CredHub: the store creates entry if no such entry exists and writes value
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	_, err := s.sfGroup.Do(s.config.Namespace+"/"+name, func() (interface{}, error) {
		return nil, s.put(ctx, name, value)
	})
	return err
}

// CredHub "Set a Value Credential":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_set_a_value_credential
// - `credhub curl -X=PUT -p "/api/v1/data" -d='{"name":"/test-namespace/key-1","type":"value","value":"1"}`
func (s *Store) put(ctx context.Context, name string, value []byte) error {
	uri := "/api/v1/data"
	data := map[string]string{
		"name":  s.config.Namespace + "/" + name,
		"type":  "value",
		"value": BytesToJsonString(value, s.config.ForceBase64ValuesEncoding),
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	resp := s.client.DoRequest(ctx, http.MethodPut, uri, bytes.NewBuffer(payload))
	defer resp.CloseResource()
	if resp.err != nil {
		return resp.err
	}

	if resp.IsStatusCode2xx() {
		return nil
	} else {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to set entry (status: %s, response: %s)", resp.Status, string(bodyBytes))
	}
}

// Get returns the value associated with the given key.
// It returns ErrNotExists if no such entry exists.
//
// CredHub "Get a Credential by Name":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_get_a_credential_by_name
// - `credhub curl -X=GET -p "/api/v1/data?name=/test-namespace/key-4&current=true"`
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	uri := fmt.Sprintf("/api/v1/data?current=true&name=%s/%s", s.config.Namespace, name)
	resp := s.client.DoRequest(ctx, http.MethodGet, uri, nil)
	defer resp.CloseResource()
	if resp.err != nil {
		return nil, resp.err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, kes.ErrKeyNotFound
	} else if !resp.IsStatusCode2xx() {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get entry (status: %s, response: %s)", resp.Status, string(bodyBytes))
	}
	var responseData struct {
		Data []struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, err
	}

	if len(responseData.Data) == 0 {
		return nil, kv.ErrNotExists
	}
	if len(responseData.Data) > 1 {
		return nil, fmt.Errorf("received multiple entries (%d) for the same key", len(responseData.Data))
	}
	return JsonStringToBytes(responseData.Data[0].Value)
}

// Delete deletes the key and the associated value from the storage.
// It returns ErrNotExists if no such entry exists.
//
// CredHub "Delete a Credential":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_delete_a_credential
// - `credhub curl -X=DELETE -p "/api/v1/data?name=/test-namespace/key-2"`
func (s *Store) Delete(ctx context.Context, name string) error {
	uri := fmt.Sprintf("/api/v1/data?name=%s/%s", s.config.Namespace, name)
	resp := s.client.DoRequest(ctx, http.MethodDelete, uri, nil)
	defer resp.CloseResource()
	if resp.err != nil {
		return resp.err
	}

	if resp.StatusCode == http.StatusNotFound {
		return kes.ErrKeyNotFound
	} else if !resp.IsStatusCode2xx() {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to delete entry: %s, response: %s", resp.Status, string(bodyBytes))
	}
	return nil
}

// List returns an Iter enumerating the stored entries.
//
// CredHub "Find a Credential by Path":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_find_a_credential_by_path
// - `credhub curl -X=GET -p "/api/v1/data?path=/test-namespace/"`
func (s *Store) List(ctx context.Context) (kv.Iter[string], error) {
	pathPrefix := s.config.Namespace + "/"
	uri := fmt.Sprintf("/api/v1/data?path=%s", pathPrefix)
	resp := s.client.DoRequest(ctx, http.MethodGet, uri, nil)
	defer resp.CloseResource()
	if resp.err != nil {
		return nil, resp.err
	}

	if !resp.IsStatusCode2xx() {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list entries (status: %s, response: %s)", resp.Status, string(bodyBytes))
	}
	var responseData struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, err
	}

	keys := make([]string, len(responseData.Credentials))
	for i, credential := range responseData.Credentials {
		keys[i] = strings.TrimPrefix(credential.Name, pathPrefix)
	}
	return &keysIter{keys: keys, index: 0, ctx: ctx}, nil
}

type keysIter struct {
	keys  []string
	index int
	ctx   context.Context
}

func (s *keysIter) Next() (string, bool) {
	key := ""
	if s.index < len(s.keys) {
		key = s.keys[s.index]
		s.index++
	}
	return key, s.index < len(s.keys)
}

func (s *keysIter) Close() error {
	s.keys = nil
	return s.ctx.Err()
}

// Close  terminate or release resources that were opened or acquired.
func (s *Store) Close() error { return nil }

// This line ensures that the Store type implements the kv.Store interface.
// It will fail at compile time if the contract is not satisfied.
var _ kv.Store[string, []byte] = (*Store)(nil)
