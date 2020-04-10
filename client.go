// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Client is a KES client. Usually, a new client is
// instantiated via the NewClient or NewClientWithConfig
// functions.
//
// In general, a client just requires:
// •  a KES server endpoint
// •  a X.509 certificate for authentication.
//
// However, custom transport protcols, timeouts,
// connection pooling, etc. can be specified via
// a custom http.RoundTripper. For example:
//   client := &Client{
//       Endpoint:   "https:127.0.0.1:7373",
//       HTTPClient: http.Client{
//           Transport: &http.Transport{
//              // specify custom behavior...
//
//              TLSClientConfig: &tls.Config{
//                  Certificates: []tls.Certificates{clientCert},
//              },
//           },
//       },
//    }
//
// A custom transport protocol can be used via a
// custom implemention of the http.RoundTripper
// interface.
type Client struct {
	// Endpoint is the KES server HTTPS endpoint.
	// For example: https://127.0.0.1:7373
	Endpoint string

	// HTTPClient is the HTTP client.
	//
	// The HTTP client uses its http.RoundTripper
	// to send requests resp. receive responses.
	//
	// It must not be modified concurrently.
	HTTPClient http.Client
}

// NewClient returns a new KES client with the given
// KES server endpoint that uses the given TLS certficate
// mTLS authentication.
//
// The TLS certificate must be valid for client authentication.
//
// NewClient uses an http.Transport with reasonable defaults.
func NewClient(endpoint string, cert tls.Certificate) *Client {
	return NewClientWithConfig(endpoint, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	})
}

// NewClientWithConfig returns a new KES client with the
// given KES server endpoint that uses the given TLS config
// for mTLS authentication.
//
// Therefore, the config.Certificates must contain a TLS
// certificate that is valid for client authentication.
//
// NewClientWithConfig uses an http.Transport with reasonable
// defaults.
func NewClientWithConfig(endpoint string, config *tls.Config) *Client {
	return &Client{
		Endpoint: endpoint,
		HTTPClient: http.Client{
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
				TLSClientConfig:       config,
			},
		},
	}
}

// Version tries to fetch the version information from the
// KES server.
func (c *Client) Version() (string, error) {
	resp, err := c.HTTPClient.Get(fmt.Sprintf("%s/version", c.Endpoint))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", parseErrorResponse(resp)
	}

	type Response struct {
		Version string `json:"version"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// CreateKey tries to create a new master key with
// the specified name. The master key will be generated
// by the KES server.
func (c *Client) CreateKey(name string) error {
	url := fmt.Sprintf("%s/v1/key/create/%s", c.Endpoint, name)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// ImportKey tries to import key as new master key with
// the specified name. In contrast to CreateKey, the client
// specifies, and therefore, knows the value of the master
// key.
func (c *Client) ImportKey(name string, key []byte) error {
	type Request struct {
		Bytes []byte `json:"bytes"`
	}
	body, err := json.Marshal(Request{
		Bytes: key,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/key/import/%s", c.Endpoint, name)
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) DeleteKey(name string) error {
	url := fmt.Sprintf("%s/v1/key/delete/%s", c.Endpoint, name)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) GenerateDataKey(name string, context []byte) ([]byte, []byte, error) {
	type Request struct {
		Context []byte `json:"context"`
	}
	body, err := json.Marshal(Request{
		Context: context,
	})
	if err != nil {
		return nil, nil, err
	}

	url := fmt.Sprintf("%s/v1/key/generate/%s", c.Endpoint, name)
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	type Response struct {
		Plaintext  []byte `json:"plaintext"`
		Ciphertext []byte `json:"ciphertext"`
	}
	const limit = 1 << 20
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, nil, err
	}
	return response.Plaintext, response.Ciphertext, nil
}

func (c *Client) DecryptDataKey(name string, ciphertext, context []byte) ([]byte, error) {
	type Request struct {
		Ciphertext []byte `json:"ciphertext"`
		Context    []byte `json:"context"`
	}
	body, err := json.Marshal(Request{
		Ciphertext: ciphertext,
		Context:    context,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/key/decrypt/%s", c.Endpoint, name)
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	type Response struct {
		Plaintext []byte `json:"plaintext"`
	}
	const limit = 32 * 1024
	var response Response
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response.Plaintext, nil
}

func (c *Client) WritePolicy(name string, policy *Policy) error {
	content, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/v1/policy/write/%s", c.Endpoint, name)
	resp, err := c.HTTPClient.Post(url, "application/json", bytes.NewReader(content))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) ReadPolicy(name string) (*Policy, error) {
	resp, err := c.HTTPClient.Get(fmt.Sprintf("%s/v1/policy/read/%s", c.Endpoint, name))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	const limit = 32 * 1024 * 1024
	decoder := json.NewDecoder(io.LimitReader(resp.Body, limit))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err = decoder.Decode(&policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (c *Client) ListPolicies(pattern string) ([]string, error) {
	resp, err := c.HTTPClient.Get(fmt.Sprintf("%s/v1/policy/list/%s", c.Endpoint, url.PathEscape(pattern)))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	defer resp.Body.Close()

	const limit = 64 * 1024 * 1024
	var policies []string
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&policies); err != nil {
		return nil, err
	}
	return policies, nil
}

func (c *Client) DeletePolicy(name string) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/policy/delete/%s", c.Endpoint, name), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) AssignIdentity(policy string, id Identity) error {
	url := fmt.Sprintf("%s/v1/identity/assign/%s/%s", c.Endpoint, policy, id.String())
	resp, err := c.HTTPClient.Post(url, "application/json", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) ListIdentities(pattern string) (map[Identity]string, error) {
	resp, err := c.HTTPClient.Get(fmt.Sprintf("%s/v1/identity/list/%s", c.Endpoint, url.PathEscape(pattern)))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	const limit = 64 * 1024 * 1024
	response := map[Identity]string{}
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) ForgetIdentity(id Identity) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/identity/forget/%s", c.Endpoint, id.String()), nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// TraceAuditLog subscribes to the KES server audit
// log and returns a stream of audit events on success.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// audit log.
func (c *Client) TraceAuditLog() (*AuditStream, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/log/audit/trace", c.Endpoint), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewAuditStream(resp.Body), nil
}

// TraceErrorLog subscribes to the KES server error
// log and returns a stream of error events on success.
//
// It returns ErrNotAllowed if the client does not
// have sufficient permissions to subscribe to the
// error log.
func (c *Client) TraceErrorLog() (*ErrorStream, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/log/error/trace", c.Endpoint), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}
	return NewErrorStream(resp.Body), nil
}
