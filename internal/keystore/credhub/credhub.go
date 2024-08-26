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
	"github.com/google/uuid"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/keystore"
	kesdk "github.com/minio/kms-go/kes"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	contentType     = "Content-Type"
	applicationJSON = "application/json"
)

// Config holds the configuration settings for connecting to a CredHub service.
type Config struct {
	BaseURL                   string // The base URL endpoint of the CredHub service.
	EnableMutualTLS           bool   // If set to true, enables mutual TLS.
	ClientCertFilePath        string // Path to the client's certificate file used for mutual TLS authentication.
	ClientKeyFilePath         string // Path to the client's private key file used for mutual TLS authentication.
	ServerInsecureSkipVerify  bool   // If set to true, server's certificate will not be verified against the provided CA certificate.
	ServerCaCertFilePath      string // Path to the CA certificate file for verifying the CredHub server's certificate.
	Namespace                 string // A namespace within CredHub where credentials are stored.
	ForceBase64ValuesEncoding bool   // If set to true, forces encoding of all the values as base64 before storage.
}

// Certs contains the certificates needed for mutual TLS authentication.
type Certs struct {
	ServerCaCert  *x509.Certificate
	ClientKeyPair tls.Certificate
}

// Validate checks the configuration for correctness and loads the necessary certificates for mutual TLS authentication.
// It returns a Certs object containing the server CA certificate and client key pair, or an error if validation fails.
func (c *Config) Validate() (*Certs, error) {
	certs := &Certs{}
	if c.BaseURL == "" {
		return certs, errors.New("credhub config: `BaseURL` can't be empty")
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
			return nil, fmt.Errorf("credhub config: error parsing the certificate '%s': %v", "ServerCaCertFilePath", err)
		}
	}
	if c.EnableMutualTLS {
		if c.ClientCertFilePath == "" || c.ClientKeyFilePath == "" {
			return certs, errors.New("credhub config: `ClientCertFilePath` and `ClientKeyFilePath` can't be empty when `EnableMutualTLS` is true")
		}
		cCertPemBytes, cCertDerBytes, err := c.validatePemFile(c.ClientCertFilePath, "ClientCertFilePath")
		if err != nil {
			return certs, err
		}
		_, err = x509.ParseCertificate(cCertDerBytes)
		if err != nil {
			return nil, fmt.Errorf("credhub config: error parsing the certificate '%s': %v", "ClientCertFilePath", err)
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
		return pemBytes, nil, fmt.Errorf("credhub config: failed to load PEM file '%s'='%s': %v", name, path, err)
	}
	derBlock, _ := pem.Decode(pemBytes)
	if derBlock == nil {
		return pemBytes, nil, fmt.Errorf("credhub config: failed to decode the '%s'='%s' from PEM format, no PEM data found", name, path)
	}
	return pemBytes, derBlock.Bytes, nil
}

// Store represents a layer that interacts with a CredHub service using HTTP protocol.
type Store struct {
	LastError error
	config    *Config
	client    httpClient
	sfGroup   singleflight.Group
}

// NewStore creates a new instance of Store, initializing it with the provided configuration.
// It returns an error if the HTTP client initialization fails.
func NewStore(_ context.Context, config *Config) (*Store, error) {
	client, err := newHTTPMTLSClient(config)
	if err != nil {
		return nil, err
	}
	return &Store{config: config, client: client}, nil
}

// Status returns the current state of the KeyStore.
//
// CredHub "Get Server Status":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_get_server_status
// - `credhub curl -X=GET -p /health`
func (s *Store) Status(ctx context.Context) (kes.KeyStoreState, error) {
	uri := "/health"
	startTime := time.Now()
	resp := s.client.doRequest(ctx, http.MethodGet, uri, nil)
	defer resp.closeResource()
	if resp.err != nil {
		return kes.KeyStoreState{Latency: 0}, resp.err
	}
	state := kes.KeyStoreState{
		Latency: time.Since(startTime),
	}

	if resp.isStatusCode2xx() {
		var responseData struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(resp.body).Decode(&responseData); err != nil {
			return state, fmt.Errorf("failed to parse response: %v", err)
		}
		if responseData.Status == "UP" {
			return state, nil
		}
		return state, fmt.Errorf("CredHub is not UP, status: %s", responseData.Status)

	}
	return state, fmt.Errorf("the CredHub (%s) is not healthy, status: %s", uri, resp.status)
}

// Create creates a new entry with the given name if and only
// if no such entry exists.
// Otherwise, Create returns kes.ErrKeyExists.
//
// CredHub: there is no method to do it, implemented workaround with limitations
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	return s.create(ctx, name, value, uuid.New().String())
}

func (s *Store) create(ctx context.Context, name string, value []byte, operationID string) error {
	_, err := s.sfGroup.Do(s.config.Namespace+"/"+name, func() (interface{}, error) {
		_, err := s.Get(ctx, name)
		switch {
		case err == nil:
			return nil, fmt.Errorf("key '%s' already exists: %w", name, kesdk.ErrKeyExists)
		case errors.Is(err, kesdk.ErrKeyNotFound):
			return nil, s.put(ctx, name, value, operationID)
		default:
			return nil, err
		}
	})
	return err
}

// CredHub "Set a Value Credential":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_set_a_value_credential
// - `credhub curl -X=PUT -p "/api/v1/data" -d='{"name":"/test-namespace/key-1","type":"value","value":"1"}`
func (s *Store) put(ctx context.Context, name string, value []byte, operationID string) error {
	uri := "/api/v1/data"
	valueStr := bytesToJSONString(value, s.config.ForceBase64ValuesEncoding)
	data := map[string]interface{}{
		"name":  s.config.Namespace + "/" + name,
		"type":  "value",
		"value": valueStr,
		"metadata": map[string]string{
			"operation_id": operationID,
		},
	}
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	resp := s.client.doRequest(ctx, http.MethodPut, uri, bytes.NewBuffer(payload))
	defer resp.closeResource()
	if resp.err != nil {
		return resp.err
	}

	if resp.isStatusCode2xx() {
		var responseData struct {
			Value    string `json:"value"`
			Metadata struct {
				OperationID string `json:"operation_id"`
			} `json:"metadata"`
		}
		if err := json.NewDecoder(resp.body).Decode(&responseData); err != nil {
			return fmt.Errorf("can't decode response of put entry (status: %s)", resp.status)
		}
		if responseData.Value != valueStr {
			return fmt.Errorf("key '%s' was inserted but overwritten by other process (the returned value is different from the the one sent): %w", name, kesdk.ErrKeyExists)
		}
		if responseData.Metadata.OperationID != operationID {
			return fmt.Errorf("key '%s' was inserted but overwritten by other process (operation ID %s != %s): %w", name, responseData.Metadata.OperationID, operationID, kesdk.ErrKeyExists)
		}
		return nil

	}
	return fmt.Errorf("failed to put entry (status: %s)", resp.status)
}

// Delete removes the entry. It may return either no error or
// kes.ErrKeyNotFound if no such entry exists.
//
// CredHub "Delete a Credential":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_delete_a_credential
// - `credhub curl -X=DELETE -p "/api/v1/data?name=/test-namespace/key-2"`
func (s *Store) Delete(ctx context.Context, name string) error {
	uri := fmt.Sprintf("/api/v1/data?name=%s/%s", s.config.Namespace, name)
	resp := s.client.doRequest(ctx, http.MethodDelete, uri, nil)
	defer resp.closeResource()
	if resp.err != nil {
		return resp.err
	}

	if resp.statusCode == http.StatusNotFound {
		return kesdk.ErrKeyNotFound
	} else if !resp.isStatusCode2xx() {
		return fmt.Errorf("failed to delete entry: %s", resp.status)
	}
	return nil
}

// Get returns the value for the given name. It returns
// kes.ErrKeyNotFound if no such entry exits.
//
// CredHub "Get a Credential by Name":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_get_a_credential_by_name
// - `credhub curl -X=GET -p "/api/v1/data?name=/test-namespace/key-4&current=true"`
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	uri := fmt.Sprintf("/api/v1/data?current=true&name=%s/%s", s.config.Namespace, name)
	resp := s.client.doRequest(ctx, http.MethodGet, uri, nil)
	defer resp.closeResource()
	if resp.err != nil {
		return nil, resp.err
	}

	if resp.statusCode == http.StatusNotFound {
		return nil, kesdk.ErrKeyNotFound
	} else if !resp.isStatusCode2xx() {
		return nil, fmt.Errorf("failed to get entry (status: %s)", resp.status)
	}
	var responseData struct {
		Data []struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.body).Decode(&responseData); err != nil {
		return nil, err
	}

	if len(responseData.Data) == 0 {
		return nil, kesdk.ErrKeyNotFound
	}
	if len(responseData.Data) > 1 {
		return nil, fmt.Errorf("received multiple entries (%d) for the same key", len(responseData.Data))
	}
	return jsonStringToBytes(responseData.Data[0].Value)
}

// List returns the first n key names, that start with the given
// prefix, and the next prefix from which the listing should
// continue.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty.
//
// CredHub "Find a Credential by Name-Like":
// - https://docs.cloudfoundry.org/api/credhub/version/main/#_find_a_credential_by_name_like
// - `credhub curl -X=GET -p "/api/v1/data?path=/test-namespace/"`
func (s *Store) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	pathPrefix := s.config.Namespace + "/"
	uri := fmt.Sprintf("/api/v1/data?name-like=%s%s", pathPrefix, prefix)
	resp := s.client.doRequest(ctx, http.MethodGet, uri, nil)
	defer resp.closeResource()
	if resp.err != nil {
		return nil, "", resp.err
	}

	if !resp.isStatusCode2xx() {
		return nil, "", fmt.Errorf("failed to list entries (status: %s)", resp.status)
	}
	var responseData struct {
		Credentials []struct {
			Name string `json:"name"`
		} `json:"credentials"`
	}
	if err := json.NewDecoder(resp.body).Decode(&responseData); err != nil {
		return nil, "", err
	}

	var names []string
	for _, credential := range responseData.Credentials {
		names = append(names, strings.TrimPrefix(credential.Name, pathPrefix))
	}
	resNames, resPrefix, err := keystore.List(names, prefix, n)
	return resNames, resPrefix, err
}

// Close  terminate or release resources that were opened or acquired.
func (s *Store) Close() error { return nil }
