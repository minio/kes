package vault

import (
	"context"
	"encoding/base64"
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
	store.client = client

	status, err := store.client.Sys().Health()
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

	go store.checkStatus(context, store.StatusPing)
	go store.renewAuthToken(context, *store.AppRole, ttl)
	return nil
}

func (store *KeyStore) Get(name string) (key.Secret, error) {
	if store.client == nil {
		panic("vault: key store is not connected to vault")
	}
	if store.sealed {
		return key.Secret{}, key.ErrStoreSealed
	}

	// First check whether there is a secret key in the cache.
	store.lock.RLock()
	if secret, ok := store.cache[name]; ok {
		store.lock.RUnlock()
		return secret, nil
	}
	store.lock.RUnlock()

	// Since we haven't found the requested secret key in the cache
	// we reach out to Vault's K/V store and fetch it from there.
	entry, err := store.client.Logical().Read(fmt.Sprintf("/kv/%s/%s", store.Name, name))
	if err != nil || entry == nil {
		// Vault will not return an error if e.g. the key existed but has
		// been deleted. However, it will return (nil, nil) in this case.
		if err == nil && entry == nil {
			return key.Secret{}, key.ErrKeyNotFound
		}
		return key.Secret{}, err
	}

	// Verify that we got a well-formed secret key from Vault
	v, ok := entry.Data[name]
	if !ok || v == nil {
		return key.Secret{}, errors.New("vault: missing secret key")
	}
	s, ok := v.(string)
	if !ok {
		return key.Secret{}, errors.New("vault: malformed secret key")
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(decodedSecret) != 32 {
		return key.Secret{}, errors.New("vault: malformed secret key")
	}

	var secret key.Secret
	copy(secret[:], decodedSecret)

	// Now add the secret key to the cache to
	// make subsequent calls faster.
	store.lock.Lock()
	defer store.lock.Unlock()

	// First, we have to check whether the secret key has
	// been added in the meantime by another request. If so,
	// we use the secret key that is already in the cache since
	// it may has been used already.
	// There is anyway no way we can handle a situation where
	// two different keys have the same name safely. So we just
	// honor whatever is cached and only add a new cache entry
	// if none exists.
	if sec, ok := store.cache[name]; ok {
		return sec, nil
	}

	if store.cache == nil {
		store.cache = map[string]key.Secret{}
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

	store.lock.Lock()
	defer store.lock.Unlock()

	// First, we check whether there is a secret key in the cache.
	if store.cache == nil {
		store.cache = map[string]key.Secret{}
	}
	if _, ok := store.cache[name]; ok {
		return key.ErrKeyExists
	}

	// Second we try to check whether key exists on the K/V store.
	// If so, we must not overwrite it.
	location := fmt.Sprintf("/kv/%s/%s", store.Name, name)

	// Vault will return nil for the secret as well as a nil-error
	// if the specified entry does not exist.
	// More specifically the Vault server + client behaves as following:
	//  - If the entry does not exist (b/c it never existed) the server
	//    returns 404 and the client returns the tuple (nil, nil).
	//  - If the entry does not exist (b/c it existed before but has
	//    been deleted) the server returns 404 but response with a
	//    "secret". The client will still parse the response body (even
	//    though 404) and return (nil, nil) if the body is empty or
	//    the secret contains no data (and no "warnings" or "errors")
	//
	// Therefore, we check whether the client returns a nil error
	// and a non-nil "secret". In this case, the secret key already
	// exists.
	// But when the client returns an error it does not mean that
	// the entry does not exist but that some other error (e.g.
	// network error) occurred.
	switch s, err := store.client.Logical().Read(location); {
	case err == nil && s != nil:
		return key.ErrKeyExists
	case err != nil:
		return err
	}

	// Finally, we create the secret key since it seems that it
	// doesn't exist. However, this is just an assumption since
	// another key server may have created that key in the meantime.
	// Since there is now way we can detect that reliable we require
	// that whoever has the permission to create keys does that in
	// a non-racy way.
	_, err := store.client.Logical().Write(location, map[string]interface{}{
		name: base64.StdEncoding.EncodeToString(secret[:]),
	})
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

	// Vault will not return an error if an entry does not
	// exist. Instead, it responds with 204 No Content and
	// no body. In this case the client also returns a nil-error
	// Therefore, we can just try to delete it in any case.
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
