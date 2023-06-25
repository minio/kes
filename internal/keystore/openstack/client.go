package openstack

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

// authToken is a Barbican authentication token.
// It can be used to authenticate API requests.
type authToken struct {
	Key    string
	Expiry time.Time
}

// client is a Barbican REST API client
// responsible for fetching and renewing
// authentication tokens.
type client struct {
	xhttp.Retry

	lock  sync.Mutex
	token authToken
}

// Add auth header to request
func (c *client) setAuthHeader(ctx context.Context, config Config, h *http.Header) error {
	if c.token.Expiry.Unix() < time.Now().Unix() {
		err := c.Authenticate(ctx, config)
		if err != nil {
			return err
		}
	}
	h.Add("X-Auth-Token", string(c.token.Key))
	return nil
}

// Authenticate tries to obtain a new authentication token
// from the given Barbican endpoint via the given credentials.
//
// Authenticate should be called to obtain the first authentication
// token. This token can then be renewed via RenewApiToken.
func (c *client) Authenticate(ctx context.Context, config Config) error {
	r := AuthRequest{}
	r.Auth.Identity.Methods = []string{"password"}
	r.Auth.Identity.Password.User.Domain.Name = config.Login.UserDomainName
	r.Auth.Identity.Password.User.Name = config.Login.Username
	r.Auth.Identity.Password.User.Password = config.Login.Password
	r.Auth.Scope.Project.Domain.Name = config.Login.ProjectDomain
	r.Auth.Scope.Project.Name = config.Login.ProjectName

	body, err := json.Marshal(&r)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v3/auth/tokens", config.Login.AuthUrl)
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

	if resp.StatusCode != http.StatusCreated {
		err := parseErrorResponse(resp)
		return fmt.Errorf("%s: %v", resp.Status, err)
	}

	const MaxSize = 1 * mem.MiB // An auth. token response should not exceed 1 MiB
	var response AuthResponse
	if err = json.NewDecoder(mem.LimitReader(resp.Body, MaxSize)).Decode(&response); err != nil {
		return err
	}
	if response.Token.ExpiresAt == "" {
		return errors.New("server response does not contain a token expiry")
	}
	expiry, err := time.Parse(time.RFC3339Nano, response.Token.ExpiresAt)
	if err != nil || expiry.Unix() < time.Now().Unix() {
		return errors.New("server response does not contain a valid token expiry")
	}

	token := resp.Header.Get("x-subject-token")
	if token == "" {
		return errors.New("server response does not contain a token header")
	}

	c.lock.Lock()
	c.token = authToken{
		Key:    token,
		Expiry: expiry,
	}
	c.lock.Unlock()
	return nil
}
