// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"context"
	"errors"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// client is a generic vault client that
// implements common functionality for
// the vault.Store and vault.KMS
type client struct {
	*vaultapi.Client

	sealed atomic.Bool
}

// Sealed returns true if the most recently fetched vault
// health status indicates that the vault server is sealed.
//
// Note that the most recently fetchted vault status may not
// reflect the current status of the vault server - because it
// may have changed in the meantime.
//
// If the vault health status hasn't been queried ever then
// Sealed returns false.
func (c *client) Sealed() bool { return c.sealed.Load() }

// CheckStatus keeps fetching the vault health status every delay
// unit of time until  <-ctx.Done() returns.
//
// Since CheckStatus starts an endless for-loop users should usually
// invoke CheckStatus in a separate go routine:
//
//	go client.CheckStatus(ctx, 10 * time.Second)
//
// If the delay == 0 CheckStatus uses a 10s delay by default.
func (c *client) CheckStatus(ctx context.Context, delay time.Duration) {
	if delay == 0 {
		delay = 10 * time.Second
	}

	ticker := time.NewTicker(delay)
	defer ticker.Stop()

	for {
		client, _ := c.CloneWithHeaders()
		if client != nil {
			// See vault.Store.Status() for more info on namespace handling.
			client.ClearNamespace()
			status, err := client.Sys().HealthWithContext(ctx)
			if err == nil {
				c.sealed.Store(status.Sealed)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Authenticate tries to fetch a auth. token with an associated TTL
// from the vault server by using the login AppRole credentials.
//
// To renew the auth. token see: client.RenewToken(...).
func (c *client) AuthenticateWithAppRole(login *AppRole) authFunc {
	return func(ctx context.Context) (*vaultapi.Secret, error) {
		client := c.Client
		switch {
		case login.Namespace == "/": // Treat '/' as the root namespace
			client = client.WithNamespace("") // Clear namespace
		case login.Namespace != "":
			client = client.WithNamespace(login.Namespace)
		}

		secret, err := client.Logical().WriteWithContext(ctx, path.Join("auth", login.Engine, "login"), map[string]interface{}{
			"role_id":   login.ID,
			"secret_id": login.Secret,
		})
		if secret == nil && err == nil {
			// The Vault SDK eventually returns no error but also no
			// secret. In this case have to return a (not very helpful)
			// error to signal that the authentication failed - for some
			// (unknown) reason.
			return nil, errors.New("vault: authentication failed: SDK returned no error but also no token")
		}
		return secret, err
	}
}

func (c *client) AuthenticateWithK8S(login *Kubernetes) authFunc {
	return func(ctx context.Context) (*vaultapi.Secret, error) {
		client := c.Client
		switch {
		case login.Namespace == "/": // Treat '/' as the root namespace
			client = client.WithNamespace("") // Clear namespace
		case login.Namespace != "":
			client = client.WithNamespace(login.Namespace)
		}

		jwt := login.JWT
		if strings.ContainsRune(jwt, '/') || strings.ContainsRune(jwt, os.PathSeparator) {
			jwtBytes, err := os.ReadFile(jwt)
			if err != nil {
				return nil, err
			}
			jwt = string(jwtBytes)
		}

		secret, err := client.Logical().WriteWithContext(ctx, path.Join("auth", login.Engine, "login"), map[string]interface{}{
			"role": login.Role,
			"jwt":  jwt,
		})
		if secret == nil && err == nil {
			// The Vault SDK eventually returns no error but also no
			// secret. In this case have to return a (not very helpful)
			// error to signal that the authentication failed - for some
			// (unknown) reason.
			return nil, errors.New("vault: authentication failed: SDK returned no error but also no token")
		}
		return secret, err
	}
}

// authFunc implements a Vault authentication method.
//
// It returns a secret with a Vault authentication token
// and its time-to-live (TTL) or an error explaining why
// the authentication attempt failed.
type authFunc func(context.Context) (*vaultapi.Secret, error)

// RenewToken tries to renew the Vault auth token periodically
// based on its TTL. If TTL is zero, RenewToken returns early
// because tokens without a TTL are long-lived and don't need
// to be renewed.
//
// If the vault server gets sealed, RenewToken stops
// and waits until it is unsealed again. Therefore,
// a client should have started a client.CheckStatus(...)
// go routine in the background.
//
// Since RenewToken starts a endless for-loop users should
// usually invoke CheckStatus in a separate go routine:
//
//	go client.RenewToken(ctx, login, ttl)
func (c *client) RenewToken(ctx context.Context, authenticate authFunc, secret *vaultapi.Secret) {
	s := secret
	ttl, _ := s.TokenTTL()
	if ttl == 0 {
		return // Token has no TTL. Hence, we do not need to renew it. (long-lived)
	}

	const (
		Retry = 3                // Retry token renewal N times before re-authenticating.
		Delay = 30 * time.Second // Wait a certain amount of time before using a new token to account for Vault replication lag
	)
	for {
		// If Vault is sealed we have to wait
		// until it is unsealed again.
		//
		// Users should start client.CheckStatus() in
		// another go routine to unblock this for-loop
		// once vault becomes unsealed again.
		if c.Sealed() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}

		// If the token is about to expire, we re-auth immediately. We also don't wait
		// for Vault not to sync up because the existing token will become invalid.
		if ttl < Delay {
			if s, _ = authenticate(ctx); s != nil {
				ttl, _ = s.TokenTTL()
				token, _ := s.TokenID()
				c.SetToken(token) // SetToken is safe to call from different go routines
			}

			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second): // In case of an auth failure, wait 3s and retry
			}
			continue
		}

		renewIn := 80 * (ttl / 100)          // Renew token after 80% of its TTL has passed
		delay := min((ttl-renewIn)/2, Delay) // Delay usage of renewed token but not beyond expiry
		ttl = 0

		select {
		case <-ctx.Done():
			return
		case <-time.After(renewIn):
			// Try to renew token, if renewable. Otherwise, or if renewal
			// fails try to re-authenticate.
			if ok, _ := s.TokenIsRenewable(); ok {
				for i := 0; i < Retry; i++ {
					var err error
					s, err = c.Auth().Token().RenewSelfWithContext(ctx, 0)
					if err == nil {
						break
					}
					if resp, ok := err.(*vaultapi.ResponseError); ok && resp.StatusCode >= 400 && resp.StatusCode < 500 {
						break // Don't retry when we receive a 4xx response
					}
				}
				if s == nil {
					s, _ = authenticate(ctx)
				}
			} else {
				s, _ = authenticate(ctx)
			}

			if s != nil {
				ttl, _ = s.TokenTTL()
				token, _ := s.TokenID()

				// Wait before we use the new auth. token. This accounts
				// for replication lag between the Vault nodes and allows
				// them to sync the token across the entire cluster.
				// However, we must not wait longer than the remaining lifetime
				// of the currently used token.
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				c.SetToken(token) // SetToken is safe to call from different go routines
			}
		}
	}
}
