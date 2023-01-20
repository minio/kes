// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"context"
	"errors"
	"path"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// client is a generic vault client that
// implements common functionality for
// the vault.Store and vault.KMS
type client struct {
	*vaultapi.Client

	sealed uint32 // Atomic bool: sealed == 0 is false, sealed == 1 is true
}

// Sealed returns true if the most recently fetched vault
// health status indicates that the vault server is sealed.
//
// Note that the most recently fetchted vault status may not
// reflect the current status of the vault server - because it
// may have changed in the meantime.
//
// If the vault health status hasn't been queried every then
// Sealed returns false.
func (c *client) Sealed() bool { return atomic.LoadUint32(&c.sealed) == 1 }

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

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		status, err := c.Sys().Health()
		if err == nil {
			if status.Sealed {
				atomic.StoreUint32(&c.sealed, 1)
			} else {
				atomic.StoreUint32(&c.sealed, 0)
			}
		}

		// Add the delay to wait before next health check.
		timer.Reset(delay)

		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// Authenticate tries to fetch a auth. token with an associated TTL
// from the vault server by using the login AppRole credentials.
//
// To renew the auth. token see: client.RenewToken(...).
func (c *client) AuthenticateWithAppRole(login AppRole) authFunc {
	return func() (token string, ttl time.Duration, err error) {
		secret, err := c.Logical().Write(path.Join("auth", login.Engine, "login"), map[string]interface{}{
			"role_id":   login.ID,
			"secret_id": login.Secret,
		})
		if err != nil || secret == nil {
			// The Vault SDK eventually returns no error but also no
			// secret. In this case have to return a (not very helpful)
			// error to signal that the authentication failed - for some
			// (unknown) reason.
			if err == nil {
				err = errors.New("vault: authentication failed: SDK returned no error but also no token")
			}
			return token, ttl, err
		}

		token, err = secret.TokenID()
		if err != nil {
			return token, ttl, err
		}

		ttl, err = secret.TokenTTL()
		if err != nil {
			return token, ttl, err
		}
		return token, ttl, nil
	}
}

func (c *client) AuthenticateWithK8S(login Kubernetes) authFunc {
	return func() (token string, ttl time.Duration, err error) {
		secret, err := c.Logical().Write(path.Join("auth", login.Engine, "login"), map[string]interface{}{
			"role": login.Role,
			"jwt":  login.JWT,
		})
		if err != nil || secret == nil {
			// The Vault SDK eventually returns no error but also no
			// secret. In this case have to return a (not very helpful)
			// error to signal that the authentication failed - for some
			// (unknown) reason.
			if err == nil {
				err = errors.New("vault: authentication failed: SDK returned no error but also no token")
			}
			return token, ttl, err
		}
		token, err = secret.TokenID()
		if err != nil {
			return token, ttl, err
		}

		ttl, err = secret.TokenTTL()
		if err != nil {
			return token, ttl, err
		}
		return token, ttl, nil
	}
}

// authFunc implements a Vault authentication method.
//
// It returns a Vault authentication token and its
// time-to-live (TTL) or an error explaining why
// the authentication attempt failed.
type authFunc func() (token string, ttl time.Duration, err error)

// RenewToken tries to authenticate with the given AppRole
// credentials if the given ttl is 0. Further, it keeps
// trying to renew the the client auth. token before its
// ttl expires until <-ctx.Done() returns.
//
// If the vault server becomes sealed, RenewToken stops
// and waits until it becomes unsealed again. Therefore,
// a client should have started a client.CheckStatus(...)
// go routine in the background.
//
// If the authentication fails, RenewToken tries to
// re-authenticate with the given login credentials.
// Once this re-authentication succeeds, RenewToken
// starts renewing the received token before its TTL
// expires.
// If the re-authentication fails, RenewToken retries
// the authentication after login.Retry.
//
// If login.Retry == 0, RenewToken uses 5s delay by default.
//
// Since RenewToken starts a endless for-loop users should
// usually invoke CheckStatus in a separate go routine:
//
//	go client.RenewToken(ctx, login, ttl)
func (c *client) RenewToken(ctx context.Context, authenticate authFunc, ttl, retry time.Duration) {
	if retry == 0 {
		retry = 5 * time.Second
	}

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		// If Vault is sealed we have to wait
		// until it is unsealed again.
		//
		// Users should start client.CheckStatus() in
		// another go routine to unblock this for-loop
		// once vault becomes unsealed again.
		for c.Sealed() {
			timer.Reset(time.Second)

			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}

		// If the TTL is 0 we cannot renew the token.
		// Therefore, we try to re-authenticate and
		// get a new token. We repeat that until we
		// successfully authenticate and got a token.
		if ttl == 0 {
			var (
				token string
				err   error
			)
			token, ttl, err = authenticate()
			if err != nil {
				ttl = 0 // On error, set the TTL again to 0 to re-auth. again.
				timer.Reset(retry)
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
				}
				continue
			}
			c.SetToken(token) // SetToken is safe to call from different go routines
		}

		// Now the client has a token with a non-zero TTL
		// such tht we can renew it. We repeat that until
		// the renewable process fails once. In this case
		// we try to re-authenticate again.
		for {
			timer.Reset(ttl / 2)

			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			secret, err := c.Auth().Token().RenewSelf(int(ttl.Seconds()))
			if err != nil || secret == nil {
				break
			}
			if ok, err := secret.TokenIsRenewable(); !ok || err != nil {
				break
			}
			ttl, err := secret.TokenTTL()
			if err != nil || ttl == 0 {
				break
			}
		}
		// If we exit the for-loop above set the TTL to 0 to trigger
		// a re-authentication.
		ttl = 0
	}
}
