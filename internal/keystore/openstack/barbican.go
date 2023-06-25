// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package openstack

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"aead.dev/mem"
	"github.com/minio/kes-go"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/kv"
)

// Connect establishes and returns a Store to a Barbican server
// using the given config.
func Connect(ctx context.Context, config *Config) (*Connection, error) {
	if config.Endpoint == "" {
		return nil, errors.New("barican: endpoint is empty")
	}

	var tlsConfig *tls.Config
	client := &client{
		Retry: xhttp.Retry{
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
	}

	// Authenticate and get token
	if err := client.Authenticate(ctx, *config); err != nil {
		return nil, err
	}
	return &Connection{
		config: *config,
		client: client,
	}, nil
}

// Status returns the current state of the Barbican instance.
// In particular, whether it is reachable and the network latency.
func (s *Connection) Status(ctx context.Context) (kv.State, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.Endpoint, nil)
	if err != nil {
		return kv.State{}, err
	}

	start := time.Now()
	if _, err = http.DefaultClient.Do(req); err != nil {
		return kv.State{}, &kv.Unreachable{Err: err}
	}
	return kv.State{
		Latency: time.Since(start),
	}, nil
}

// Checks if a key already exists or not, if so returns kes.ErrKeyExists
func (s *Connection) verifyKeyDoesNotExist(ctx context.Context, name string) error {
	_, err := s.Get(ctx, name)
	if err != nil {
		return kes.ErrKeyExists
	}
	return nil
}

// Create stores the given key in Barbican if and only
// if no entry with the given name exists.
//
// If no such entry exists, Create returns kes.ErrKeyExists.
func (s *Connection) Create(ctx context.Context, name string, value []byte) error {
	type Request struct {
		Name                   string `json:"name,omitempty"`                     // (optional) The name of the secret set by the user.
		Expiration             string `json:"expiration,omitempty"`               // (optional) This is a UTC timestamp in ISO 8601 format YYYY-MM-DDTHH:MM:SSZ. If set, the secret will not be available after this time.
		Algorithm              string `json:"algorithm,omitempty"`                // (optional) Metadata provided by a user or system for informational purposes.
		BitLength              int    `json:"bit_length,omitempty"`               // (optional) Metadata provided by a user or system for informational purposes. Value must be greater than zero.
		Mode                   string `json:"mode,omitempty"`                     // (optional) Metadata provided by a user or system for informational purposes.
		Payload                string `json:"payload"`                            // (optional) The secret’s data to be stored. payload_content_type must also be supplied if payload is included.
		PayloadContentType     string `json:"payload_content_type,omitempty"`     // (optional) (required if payload is included) The media type for the content of the payload. For more information see Secret Types
		PayloadContentEncoding string `json:"payload_content_encoding,omitempty"` // (optional) (required if payload is encoded) The encoding used for the payload to be able to include it in the JSON request. Currently only base64 is supported.
		SecretType             string `json:"secret_type,omitempty"`              // (optional) Used to indicate the type of secret being stored. For more information see Secret Types (default: opaque)
	}
	const (
		SecretType      = "opaque"
		ContentType     = "application/octet-stream"
		ContentEncoding = "base64"
		Algorithm       = "aes"
		BitLength       = 256
		Mode            = "cbc"
	)
	// Check if key already exists
	if err := s.verifyKeyDoesNotExist(ctx, name); err != kes.ErrKeyExists {
		return err
	}

	// Create new key
	request, err := json.Marshal(Request{
		SecretType:             SecretType,
		Name:                   name,
		Payload:                base64.StdEncoding.EncodeToString(value),
		PayloadContentType:     ContentType,
		PayloadContentEncoding: ContentEncoding,
		Algorithm:              Algorithm,
		BitLength:              BitLength,
		Mode:                   Mode,
	})
	if err != nil {
		return err
	}

	url := endpoint(s.config.Endpoint, "/v1/secrets")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(request)))
	if err != nil {
		return fmt.Errorf("barbican: failed to create key '%s': %v", name, err)
	}
	err = s.client.setAuthHeader(ctx, s.config, &req.Header)
	if err != nil {
		return fmt.Errorf("barbican: failed to create key '%s': %v", name, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("barbican: failed to create key '%s': %v", name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		switch err := parseErrorResponse(resp); {
		case err == nil:
			return fmt.Errorf("barbican: failed to create key '%s': %s (%q)", name, resp.Status, resp.StatusCode)
		default:
			return fmt.Errorf("barbican: failed to create key '%s': %v", name, err)
		}
	}
	return nil
}

// Set stores the given key at Barbican if and only
// if no entry with the given name exists.
//
// If no such entry exists, Create returns kes.ErrKeyExists.
func (s *Connection) Set(ctx context.Context, name string, value []byte) error {
	err := s.verifyKeyDoesNotExist(ctx, name)
	if err == nil {
		return s.Create(ctx, name, value)
	}
	return err
}

// Delete deletes the key associated with the given name
// from Barbican. It may not return an error if no
// entry for the given name exists.
func (s *Connection) Delete(ctx context.Context, name string) error {
	secret, err := s.get(ctx, name)
	if err != nil {
		return err
	}

	// Now, we can delete the key using its UUID.
	url := endpoint(secret.SecretRef)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	err = s.client.setAuthHeader(ctx, s.config, &req.Header)
	if err != nil {
		return fmt.Errorf("barbican: failed to delete '%s': %v", name, err)
	}

	resp, err := s.client.Do(req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("barbican: failed to delete '%s': %v", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		switch err = parseErrorResponse(resp); {
		case err == nil:
			return fmt.Errorf("barbican: failed to delete '%s': %s (%d)", name, resp.Status, resp.StatusCode)
		default:
			return fmt.Errorf("barbican: failed to delete '%s': %v", name, err)
		}
	}
	return nil
}

func (s *Connection) get(ctx context.Context, name string) (*BarbicanSecret, error) {
	url := endpoint(s.config.Endpoint, "/v1/secrets") + "?name=" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	err = s.client.setAuthHeader(ctx, s.config, &req.Header)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}

	if resp.StatusCode != http.StatusOK {
		switch err = parseErrorResponse(resp); {
		case err == nil:
			return nil, fmt.Errorf("barbican: failed to fetch '%s': %s (%d)", name, resp.Status, resp.StatusCode)
		case resp.StatusCode == http.StatusNotFound:
			return nil, kes.ErrKeyNotFound
		default:
			return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
		}
	}
	var response BarbicanSecretsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': failed to parse key metadata: %v", name, err)
	}
	if len(response.Secrets) == 0 {
		return nil, kes.ErrKeyNotFound
	}

	// now we can get the secret payload
	url = endpoint(response.Secrets[0].SecretRef, "/payload")
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	err = s.client.setAuthHeader(ctx, s.config, &req.Header)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	req.Header.Set("Accept", "text/plain")

	resp, err = s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("barbican: failed to fetch '%s': %v", name, err)
	}

	response.Secrets[0].Payload = body
	return &response.Secrets[0], nil
}

// Get returns the key associated with the given name.
//
// If there is no such entry, Get returns kes.ErrKeyNotFound.
func (s *Connection) Get(ctx context.Context, name string) ([]byte, error) {
	secret, err := s.get(ctx, name)
	if err != nil {
		return nil, err
	}
	return secret.Payload, nil
}

// List returns a new Iterator over the Barbican.
//
// The returned iterator may or may not reflect any
// concurrent changes to the Barbican - i.e.
// creates or deletes. Further, it does not provide any
// ordering guarantees.
func (s *Connection) List(ctx context.Context) (kv.Iter[string], error) {
	var cancel context.CancelCauseFunc
	ctx, cancel = context.WithCancelCause(ctx)
	values := make(chan string, 10)

	go func() {
		defer close(values)

		var next string
		const limit = 200 // We limit a listing page to 200. This an arbitrary but reasonable value.
		for {
			reqURL := endpoint(s.config.Endpoint, "/v1/secrets") + "?sort=name:asc&limit=" + fmt.Sprint(limit)
			if next != "" {
				reqURL = next
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
			if err != nil {
				cancel(fmt.Errorf("barbican: failed to list keys: %v", err))
				break
			}
			err = s.client.setAuthHeader(ctx, s.config, &req.Header)
			if err != nil {
				cancel(fmt.Errorf("barbican: failed to list keys: %v", err))
				break
			}

			resp, err := s.client.Do(req)
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				cancel(err)
				break
			}
			if err != nil {
				cancel(fmt.Errorf("barbican: barbican to list keys: %v", err))
				break
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				if err := parseErrorResponse(resp); err != nil {
					cancel(fmt.Errorf("barbican: %s: failed to parse server response: %v", resp.Status, err))
				} else {
					cancel(fmt.Errorf("barbican: failed to list keys: '%s'", fmt.Sprint(resp.StatusCode)))
				}
				break
			}

			var keys BarbicanSecretsResponse
			if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
				cancel(fmt.Errorf("barbican: failed to list keys: failed to parse server response: %v", err))
				break
			}
			if len(keys.Secrets) == 0 {
				break
			}
			for _, k := range keys.Secrets {
				select {
				case values <- k.Name:
				case <-ctx.Done():
					return
				}
			}
			next = keys.Next
			if next == "" {
				break
			}
		}
	}()
	return &iterator{
		ch:     values,
		ctx:    ctx,
		cancel: cancel,
	}, nil
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
