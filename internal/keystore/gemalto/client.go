// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gemalto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"aead.dev/mem"
	xhttp "github.com/minio/kes/internal/http"
)

// authToken is a KeySecure authentication token.
// It can be used to authenticate API requests.
type authToken struct {
	Type   string
	Value  string
	Expiry time.Duration
}

// String returns the string representation of
// the authentication token.
func (t *authToken) String() string { return fmt.Sprintf("%s %s", t.Type, t.Value) }

// client is a KeySecure REST API client
// responsible for fetching and renewing
// authentication tokens.
type client struct {
	xhttp.Retry

	lock  sync.Mutex
	token authToken
}

// Authenticate tries to obtain a new authentication token
// from the given KeySecure endpoint via the given refresh
// token.
//
// Authenticate should be called to obtain the first authentication
// token. This token can then be renewed via RenewAuthToken.
func (c *client) Authenticate(ctx context.Context, endpoint string, login Credentials) error {
	type Request struct {
		Type   string `json:"grant_type"`
		Token  string `json:"refresh_token"`
		Domain string `json:"domain"`
	}
	type Response struct {
		Type   string `json:"token_type"`
		Token  string `json:"jwt"`
		Expiry uint64 `json:"duration"` // KeySecure returns expiry in seconds
	}

	body, err := json.Marshal(Request{
		Type:   "refresh_token",
		Token:  login.Token,
		Domain: login.Domain,
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/api/v1/auth/tokens", endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, xhttp.RetryReader(bytes.NewReader(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		response, err := parseServerError(resp)
		if err != nil {
			return fmt.Errorf("%s: %v", resp.Status, err)
		}
		return fmt.Errorf("%s: %s (%d)", resp.Status, response.Message, response.Code)
	}

	const MaxSize = 1 * mem.MiB // An auth. token response should not exceed 1 MiB
	var response Response
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxSize)).Decode(&response); err != nil {
		return err
	}
	if response.Token == "" {
		return errors.New("server response does not contain an auth token")
	}
	if response.Type != "Bearer" {
		return fmt.Errorf("unexpected auth token type '%s'", response.Type)
	}
	if response.Expiry <= 0 {
		return fmt.Errorf("invalid auth token expiry '%d'", response.Expiry)
	}

	c.lock.Lock()
	c.token = authToken{
		Type:   response.Type,
		Value:  response.Token,
		Expiry: time.Duration(response.Expiry) * time.Second,
	}
	c.lock.Unlock()
	return nil
}

// RenewAuthToken tries to renew the client's authentication
// token before it expires. It blocks until <-ctx.Done() completes.
//
// Before calling RenewAuthToken the client should already have a
// authentication token. Therefore, RenewAuthToken should be called
// only after a Authenticate.
//
// RenewAuthToken tries get a new authentication token from the given
// KeySecure endpoint by presenting the given refresh token.
// It continuesly tries to renew the authentication before it expires.
//
// If RenewAuthToken fails to request or renew the client's authentication
// token then it keeps retrying and waits for the given login.Retry delay
// between each retry attempt.
//
// If login.Retry is 0 then RenewAuthToken uses a reasonable default retry delay.
func (c *client) RenewAuthToken(ctx context.Context, endpoint string, login Credentials) {
	if login.Retry == 0 {
		login.Retry = 5 * time.Second
	}
	var (
		timer *time.Timer
		err   error
	)
	for {
		if err != nil {
			timer = time.NewTimer(login.Retry)
		} else {
			c.lock.Lock()
			timer = time.NewTimer(c.token.Expiry / 2)
			c.lock.Unlock()
		}

		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			err = c.Authenticate(ctx, endpoint, login)
			timer.Stop()
		}
	}
}

// AuthToken returns an authentication token that can be
// used to authenticate API requests to a KeySecure instance.
//
// Typically, it is a JWT token and should be used as HTTP
// Authorization header value.
func (c *client) AuthToken() string {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.token.String()
}
