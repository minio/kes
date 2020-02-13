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
	"strings"
	"time"
)

type Client struct {
	addr       string
	httpClient http.Client
}

func NewClient(addr string, config *tls.Config) *Client {
	return &Client{
		addr: addr,
		httpClient: http.Client{
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
				TLSClientConfig:       config.Clone(),
			},
		},
	}
}

func (c *Client) Transport(transport http.RoundTripper) { c.httpClient.Transport = transport }

// Version tries to fetch the version information from the
// KES server.
func (c *Client) Version() (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/version", c.addr))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", c.parseErrorResponse(resp)
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
	url := fmt.Sprintf("%s/v1/key/create/%s", c.addr, name)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
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

	url := fmt.Sprintf("%s/v1/key/import/%s", c.addr, name)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) DeleteKey(name string) error {
	url := fmt.Sprintf("%s/v1/key/delete/%s", c.addr, name)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
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

	url := fmt.Sprintf("%s/v1/key/generate/%s", c.addr, name)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, c.parseErrorResponse(resp)
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

	url := fmt.Sprintf("%s/v1/key/decrypt/%s", c.addr, name)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
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
	url := fmt.Sprintf("%s/v1/policy/write/%s", c.addr, name)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(content))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) ReadPolicy(name string) (*Policy, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/v1/policy/read/%s", c.addr, name))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
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
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/v1/policy/list/%s", c.addr, url.PathEscape(pattern)))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
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
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/policy/delete/%s", c.addr, name), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) AssignIdentity(policy string, id Identity) error {
	url := fmt.Sprintf("%s/v1/identity/assign/%s/%s", c.addr, policy, id.String())
	resp, err := c.httpClient.Post(url, "application/json", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) ListIdentities(pattern string) (map[Identity]string, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/v1/identity/list/%s", c.addr, url.PathEscape(pattern)))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}

	const limit = 64 * 1024 * 1024
	response := map[Identity]string{}
	if err = json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(&response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) ForgetIdentity(id Identity) error {
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/identity/forget/%s", c.addr, id.String()), nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return c.parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) TraceAuditLog() (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/log/audit/trace", c.addr), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.parseErrorResponse(resp)
	}
	return resp.Body, nil
}

func (c *Client) parseErrorResponse(resp *http.Response) error {
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()

	const limit = 32 * 1024
	var errMsg strings.Builder
	if _, err := io.Copy(&errMsg, io.LimitReader(resp.Body, limit)); err != nil {
		return err
	}
	return fmt.Errorf("%s: %s", http.StatusText(resp.StatusCode), errMsg.String())
}
