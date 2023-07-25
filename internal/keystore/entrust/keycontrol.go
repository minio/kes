// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package entrust

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/kv"
)

// Config is a structure containing the Entrust KeyControl configuration.
type Config struct {
	// Endpoint is the URL of the KeyControl endpoint.
	Endpoint string

	// VaultID is the UUID of the KeyControl Vault.
	VaultID string

	// BoxID is the ID or name of the box inside the Vault.
	BoxID string

	// Username is the username used for authentication.
	Username string

	// Password is the password associated with the provided username.
	Password string

	// TLS holds the TLS configuration. In particular, a custom root
	// CAs may be provided.
	TLS *tls.Config
}

// Clone returns a deep copy of the Config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	return &Config{
		Endpoint: c.Endpoint,
		VaultID:  c.VaultID,
		BoxID:    c.BoxID,
		Username: c.Username,
		Password: c.Password,
		TLS:      c.TLS.Clone(),
	}
}

// Login authenticates the user and establishes a connection to KeyControl instance.
func Login(ctx context.Context, config *Config) (*KeyControl, error) {
	config = config.Clone()
	transport := &http.Transport{
		TLSClientConfig: config.TLS,
	}
	token, expiresAt, err := login(ctx, transport, config.Endpoint, config.VaultID, config.Username, config.Password)
	if err != nil {
		return nil, err
	}

	kc := &KeyControl{
		config: config,
		client: xhttp.Retry{Client: http.Client{Transport: transport}},
	}
	kc.token.Store(&token)
	if _, err := kc.Status(ctx); err != nil {
		return nil, err
	}

	go kc.refreshToken(ctx, time.Until(expiresAt))

	return kc, nil
}

// KeyControl represents a client for interacting with a KeyControl server.
type KeyControl struct {
	config *Config
	token  atomic.Pointer[string]
	client xhttp.Retry
}

var _ kv.Store[string, []byte] = (*KeyControl)(nil)

// Status returns the current state of the KeyControl instance.
// In particular, whether it is reachable and the network latency.
func (kc *KeyControl) Status(ctx context.Context) (kv.State, error) {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/GetBox/"
		VaultToken = "X-Vault-Auth"
	)
	type Request struct {
		BoxID string `json:"box_id"`
	}
	body, err := json.Marshal(Request{
		BoxID: kc.config.BoxID,
	})
	if err != nil {
		return kv.State{}, fmt.Errorf("keycontrol: failed to fetch status: %v", err)
	}
	url, err := url.JoinPath(kc.config.Endpoint, Path)
	if err != nil {
		return kv.State{}, fmt.Errorf("keycontrol: failed to fetch status: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return kv.State{}, fmt.Errorf("keycontrol: failed to fetch status: %v", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set(VaultToken, *kc.token.Load())

	start := time.Now()
	resp, err := kc.client.Do(req)
	if err != nil {
		return kv.State{}, &kv.Unreachable{
			Err: fmt.Errorf("keycontrol: failed to fetch status: %v", err),
		}
	}
	latency := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		return kv.State{}, parseErrorResponse(resp)
	}
	return kv.State{
		Latency: latency,
	}, nil
}

// Create creates the given key-value pair at the KeyControl server
// if and only if the given key does not exist. If such an entry
// already exists it returns kes.ErrKeyExists.
func (kc *KeyControl) Create(ctx context.Context, name string, key []byte) error {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/CreateSecret/"
		VaultToken = "X-Vault-Auth"
	)
	type Request struct {
		BoxID      string `json:"box_id"`
		Name       string `json:"name"`
		SecretData []byte `json:"secret_data"`
	}

	body, err := json.Marshal(Request{
		BoxID:      kc.config.BoxID,
		Name:       name,
		SecretData: key,
	})
	if err != nil {
		return fmt.Errorf("keycontrol: failed to create key: %v", err)
	}
	url, err := url.JoinPath(kc.config.Endpoint, Path)
	if err != nil {
		return fmt.Errorf("keycontrol: failed to create key: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return fmt.Errorf("keycontrol: failed to create key: %v", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set(VaultToken, *kc.token.Load())

	resp, err := kc.client.Do(req)
	if err != nil {
		return fmt.Errorf("keycontrol: failed to create key: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// Set creates the given key-value pair at the KeyControl server
// if and only if the given key does not exist. If such an entry
// already exists it returns kes.ErrKeyExists.
func (kc *KeyControl) Set(ctx context.Context, name string, key []byte) error {
	return kc.Create(ctx, name, key)
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (kc *KeyControl) Get(ctx context.Context, name string) ([]byte, error) {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/CheckoutSecret/"
		VaultToken = "X-Vault-Auth"
	)
	type Request struct {
		BoxID    string `json:"box_id"`
		SecretID string `json:"secret_id"`
	}
	type Response struct {
		Secret []byte `json:"secret_data"`
	}

	body, err := json.Marshal(Request{
		BoxID:    kc.config.BoxID,
		SecretID: name,
	})
	if err != nil {
		return nil, fmt.Errorf("keycontrol: failed to fetch key: %v", err)
	}
	url, err := url.JoinPath(kc.config.Endpoint, Path)
	if err != nil {
		return nil, fmt.Errorf("keycontrol: failed to fetch key: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("keycontrol: failed to fetch key: %v", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set(VaultToken, *kc.token.Load())

	resp, err := kc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycontrol: failed to fetch key: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, 1*mem.MB)).Decode(&response); err != nil {
		return nil, fmt.Errorf("keycontrol: failed to fetch key: %v", err)
	}
	return response.Secret, nil
}

// Delete removes a the value associated with the given key
// from the KeyControl server, if it exists.
func (kc *KeyControl) Delete(ctx context.Context, name string) error {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/DeleteSecret/"
		VaultToken = "X-Vault-Auth"
	)
	type Request struct {
		BoxID    string `json:"box_id"`
		SecretID string `json:"secret_id"`
	}

	body, err := json.Marshal(Request{
		BoxID:    kc.config.BoxID,
		SecretID: name,
	})
	if err != nil {
		return fmt.Errorf("keycontrol: failed to delete key: %v", err)
	}
	url, err := url.JoinPath(kc.config.Endpoint, Path)
	if err != nil {
		return fmt.Errorf("keycontrol: failed to delete key: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return fmt.Errorf("keycontrol: failed to delete key: %v", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set(VaultToken, *kc.token.Load())

	resp, err := kc.client.Do(req)
	if err != nil {
		return fmt.Errorf("keycontrol: failed to delete key: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return parseErrorResponse(resp)
	}
	return nil
}

// List returns a new Iterator over the names of all stored keys.
func (kc *KeyControl) List(ctx context.Context) (kv.Iter[string], error) {
	var (
		names  []string
		prefix string
		err    error
	)
	for {
		var ids []string
		ids, prefix, err = kc.list(ctx, prefix, 250)
		if err != nil {
			return nil, err
		}
		names = append(names, ids...)

		if prefix == "" || len(ids) == 0 {
			break
		}
	}
	return &iter{names: names}, nil
}

func (kc *KeyControl) list(ctx context.Context, prefix string, n int) ([]string, string, error) {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/ListSecretIds/"
		VaultToken = "X-Vault-Auth"
	)
	type Token struct {
		BoxID      string `json:"box_id"`
		ContinueAt string `json:"next_ctx"`
	}
	type Request struct {
		BoxID     string `json:"box_id"`
		N         int    `json:"max_items"`
		NextToken string `json:"next_token,omitempty"` // Must be omitted if empty
	}
	type Response struct {
		Secrets []struct {
			Name    string `json:"name"`
			Expired bool   `json:"expired"`
		}
		NextToken string `json:"next_token"`
	}

	var token string
	if prefix != "" {
		b, err := json.Marshal(Token{
			BoxID:      kc.config.BoxID,
			ContinueAt: prefix,
		})
		if err != nil {
			return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
		}
		token = base64.StdEncoding.EncodeToString(b)
	}
	body, err := json.Marshal(Request{
		BoxID:     kc.config.BoxID,
		N:         n,
		NextToken: token,
	})
	if err != nil {
		return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
	}

	url, err := url.JoinPath(kc.config.Endpoint, Path)
	if err != nil {
		return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set(VaultToken, *kc.token.Load())

	resp, err := kc.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, 10*mem.MB)).Decode(&response); err != nil {
		return nil, "", fmt.Errorf("keycontrol: failed to list keys: %v", err)
	}
	names := make([]string, len(response.Secrets))
	for _, secret := range response.Secrets {
		if !secret.Expired {
			names = append(names, secret.Name)
		}
	}
	if response.NextToken != "" {
		rawToken, err := base64.StdEncoding.DecodeString(response.NextToken)
		if err != nil {
			return nil, "", fmt.Errorf("keycontrol: failed to list keys: invalid continue token: %v", err)
		}

		var token Token
		if err = json.Unmarshal(rawToken, &token); err != nil {
			return nil, "", fmt.Errorf("keycontrol: failed to list keys: invalid continue token: %v", err)
		}
		prefix = token.ContinueAt
	} else {
		prefix = ""
	}
	return names, prefix, nil
}

// refreshToken starts to periodically renew the KeyControl authentication
// token until ctx.Done() returns.
func (kc *KeyControl) refreshToken(ctx context.Context, renew time.Duration) {
	// We don't wait until the last second of the renew internal but try
	// to renew the token early.
	// However, if the renew interval is <= 0 we use 5min as a resonable fallback.
	if renew/2 <= 0 {
		renew = 5 * time.Minute
	}
	timer := time.NewTimer(renew / 2)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			// First, we try to renew the token. However, if this fails - e.g.
			// due to the token expired or got invalidated - we authenticate
			// using username/password again.
			token, expiresAt, err := renewToken(ctx, kc.client.Transport, kc.config.Endpoint, *kc.token.Load())
			if err != nil {
				log.Default().Printf("keycontrol: failed to renew auth token: %v", err)
				token, expiresAt, err = login(ctx, kc.client.Transport, kc.config.Endpoint, kc.config.VaultID, kc.config.Username, kc.config.Password)
				if err != nil {
					log.Default().Printf("keycontrol: failed to login: %v", err)
				}
			}

			if err == nil {
				renew = time.Until(expiresAt)
				if renew/2 <= 0 {
					renew = 5 * time.Minute // Again, use 5min as fallback
				}

				timer.Reset(renew / 2)
				kc.token.Store(&token)
			}
		}
	}
}

// login authenticates to the KeyControl instance using username and password
// and returns the authentication token and the token expiry on success.
func login(ctx context.Context, rt http.RoundTripper, endpoint, vaultID, username, password string) (string, time.Time, error) {
	const (
		Method = http.MethodPost
		Path   = "/vault/1.0/Login/"
	)
	type Request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type Response struct {
		Token     string    `json:"access_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	body, err := json.Marshal(Request{
		Username: username,
		Password: password,
	})
	if err != nil {
		return "", time.Time{}, err
	}

	url, err := url.JoinPath(endpoint, Path, vaultID, "/")
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	client := xhttp.Retry{Client: http.Client{Transport: rt}}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, 1*mem.MB)).Decode(&response); err != nil {
		return "", time.Time{}, err
	}
	if response.Token == "" {
		return "", time.Time{}, errors.New("keycontrol: login failed: auth token is empty")
	}

	if response.ExpiresAt.IsZero() {
		response.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	return response.Token, response.ExpiresAt, nil
}

// renewToken renews the KeyControl authentication token and returns the
// new authentication token and the token expiry on success.
func renewToken(ctx context.Context, rt http.RoundTripper, endpoint, token string) (string, time.Time, error) {
	const (
		Method     = http.MethodPost
		Path       = "/vault/1.0/Renew/"
		VaultToken = "X-Vault-Auth"
	)
	type Response struct {
		Token     string    `json:"access_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	url, err := url.JoinPath(endpoint, Path)
	if err != nil {
		return "", time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, Method, url, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set(VaultToken, token)

	client := xhttp.Retry{Client: http.Client{Transport: rt}}
	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, parseErrorResponse(resp)
	}

	var response Response
	if err := json.NewDecoder(mem.LimitReader(resp.Body, 1*mem.MB)).Decode(&response); err != nil {
		return "", time.Time{}, err
	}
	if response.Token == "" {
		return "", time.Time{}, errors.New("keycontrol: login failed: auth token is empty")
	}

	if response.ExpiresAt.IsZero() {
		response.ExpiresAt = time.Now().Add(5 * time.Minute)
	}
	return response.Token, response.ExpiresAt, nil
}

// parseErrorResponse parses a KeyControl HTTP error response.
func parseErrorResponse(resp *http.Response) error {
	type Response struct {
		Error string `json:"error"`
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var response Response
		if err := json.NewDecoder(mem.LimitReader(resp.Body, mem.MB)).Decode(&response); err != nil {
			return err
		}
		switch {
		case resp.StatusCode == http.StatusConflict && response.Error == "Secret already exists":
			return kes.ErrKeyExists
		case resp.StatusCode == http.StatusNotFound && response.Error == "Secret not found":
			return kes.ErrKeyNotFound
		}
		return errors.New("keycontrol: " + response.Error)
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, mem.LimitReader(resp.Body, mem.MB)); err != nil {
		return err
	}
	return errors.New("keycontrol: " + resp.Status + ": " + sb.String())
}

type iter struct {
	names []string
}

func (i *iter) Next() (string, bool) {
	if len(i.names) == 0 {
		return "", false
	}

	name := i.names[0]
	i.names = i.names[1:]
	return name, true
}

func (i *iter) Close() error { return nil }
