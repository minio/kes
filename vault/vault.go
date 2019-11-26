package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aead/key"
	vaultapi "github.com/hashicorp/vault/api"
)

type AppRole struct {
	ID     string
	Secret string
	Retry  time.Duration
}

type KeyStore struct {
	Addr string

	Name string

	AppRole *AppRole

	StatusPing time.Duration

	lock  sync.RWMutex
	cache map[string]key.Secret

	client *vaultapi.Client
	sealed bool
}

func (store *KeyStore) Authenticate(context context.Context) error {
	if store.AppRole == nil {
		return errors.New("vault: no approle authentication provided")
	}
	client, err := vaultapi.NewClient(&vaultapi.Config{
		Address: store.Addr,
	})
	if err != nil {
		return err
	}

	status, err := client.Sys().Health()
	if err != nil {
		return err
	}
	store.sealed = status.Sealed

	var token string
	var ttl time.Duration
	if !status.Sealed {
		token, ttl, err = store.authenticate(*store.AppRole)
		if err != nil {
			return err
		}
		client.SetToken(token)
	}

	store.client = client
	go store.checkStatus(context, store.StatusPing)
	go store.renewAuthToken(context, *store.AppRole, ttl)
	return nil
}

func (store *KeyStore) Get(name string) (secret key.Secret, err error) {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return secret, key.ErrStoreSealed
	}

	// First check whether a master key with that key is cached.
	store.lock.RLock()
	if secret, ok := store.cache[name]; ok {
		store.lock.RUnlock()
		return secret, nil
	}
	store.lock.RUnlock()

	// Since we haven't found the requested master key in the cache
	// we reach out to Vault's K/V store and fetch it from there.
	entry, err := store.client.Logical().Read(fmt.Sprintf("/kv/%s/%s", store.Name, name))
	if err != nil {
		return secret, err
	}

	decoder := json.NewDecoder(bytes.NewReader([]byte(entry.Data[name].(string))))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&secret); err != nil {
		return secret, err
	}

	// Now add the master key to the cache to
	// make subsequent calls faster.
	store.lock.Lock()
	defer store.lock.Unlock()

	// First, we have to check that 'name' still does not
	// exist. We should not override the cache on a Get
	// when another call has added/fetched a master key
	// in between.
	if k, ok := store.cache[name]; ok {
		return k, nil
	}
	store.cache[name] = secret
	return secret, nil
}

func (store *KeyStore) Create(name string, secret key.Secret) error {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.ErrStoreSealed
	}

	content, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		name: string(content),
	}

	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache[name]; ok {
		return key.ErrKeyExists
	}

	_, err = store.client.Logical().Write(fmt.Sprintf("/kv/%s/%s", store.Name, name), payload)
	if err != nil {
		return err
	}
	store.cache[name] = secret
	return nil
}

func (store *KeyStore) Delete(name string) error {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.ErrStoreSealed
	}

	store.lock.Lock()
	defer store.lock.Unlock()

	_, err := store.client.Logical().Delete(fmt.Sprintf("/kv/%s/%s", store.Name, name))
	delete(store.cache, name)
	return err
}

func (store *KeyStore) authenticate(login AppRole) (token string, ttl time.Duration, err error) {
	secret, err := store.client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   login.ID,
		"secret_id": login.Secret,
	})
	if err != nil || secret == nil {
		if err == nil {
			// TODO: return non-nil error
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
	return token, ttl, err
}

func (store *KeyStore) checkStatus(ctx context.Context, delay time.Duration) {
	var timer *time.Timer
	for {
		status, err := store.client.Sys().Health()
		if err == nil {
			gotSealed := !store.sealed && status.Sealed
			store.sealed = status.Sealed

			if gotSealed {
				store.lock.Lock()
				store.cache = map[string]key.Secret{}
				store.lock.Unlock()
			}
		}

		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (store *KeyStore) renewAuthToken(ctx context.Context, login AppRole, ttl time.Duration) {
	for {
		// If Vault is sealed we have to wait
		// until it is unsealed again.
		// The Vault status is checked by another go routine
		// constantly by querying the Vault health status.
		for store.sealed {
			timer := time.NewTimer(1 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
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
			token, ttl, err = store.authenticate(login)
			if err != nil {
				ttl = 0
				timer := time.NewTimer(login.Retry)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				continue
			}
			store.client.SetToken(token) // SetToken is safe to call from different go routines
		}

		// Now the client has token with a non-zero TTL
		// such tht we can renew it. We repeat that until
		// the renewable process fails once. In this case
		// we try to re-authenticate again.
		timer := time.NewTimer(ttl / 2)
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			secret, err := store.client.Auth().Token().RenewSelf(int(ttl.Seconds()))
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
			timer.Reset(ttl / 2)
		}
		ttl = 0
	}
}
