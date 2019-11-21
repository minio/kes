package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aead/key/kms"
	vaultapi "github.com/hashicorp/vault/api"
)

type Config struct {
	Addr string
	Name string

	AppRole AppRole

	StatusPing time.Duration
}

type AppRole struct {
	ID     string
	Secret string
	Retry  time.Duration
}

type KeyStore struct {
	lock  sync.RWMutex
	cache map[string]kms.Key

	name   string
	client *vaultapi.Client
	sealed bool
}

func NewKeyStore(config *Config) (*KeyStore, error) {
	client, err := vaultapi.NewClient(&vaultapi.Config{
		Address: config.Addr,
	})
	if err != nil {
		return nil, err
	}

	store := &KeyStore{
		cache:  map[string]kms.Key{},
		name:   config.Name,
		client: client,
	}

	status, err := store.client.Sys().Health()
	if err != nil {
		return nil, err
	}
	store.sealed = status.Sealed

	var token string
	var ttl time.Duration
	if !status.Sealed {
		token, ttl, err = store.authenticate(config.AppRole)
		if err != nil {
			return nil, err
		}
		store.client.SetToken(token)
	}

	go store.checkStatus(config.StatusPing)
	go store.renewAuthToken(config.AppRole, ttl)
	return store, nil
}

func (store *KeyStore) Get(name string) (key kms.Key, err error) {
	if store.sealed {
		return key, kms.ErrSealed
	}

	// First check whether a master key with that key is cached.
	store.lock.RLock()
	if key, ok := store.cache[name]; ok {
		store.lock.RUnlock()
		return key, nil
	}
	store.lock.RUnlock()

	// Since we haven't found the requested master key in the cache
	// we reach out to Vault's K/V store and fetch it from there.
	entry, err := store.client.Logical().Read(fmt.Sprintf("/kv/%s/%s", store.name, name))
	if err != nil {
		return key, err
	}

	decoder := json.NewDecoder(bytes.NewReader([]byte(entry.Data["key"].(string))))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&key); err != nil {
		return key, err
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
	store.cache[name] = key
	return key, nil
}

func (store *KeyStore) Create(key kms.Key) error {
	if store.sealed {
		return kms.ErrSealed
	}

	content, err := json.Marshal(key)
	if err != nil {
		return err
	}
	payload := map[string]interface{}{
		"key": string(content),
	}

	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache[key.Name]; ok {
		return kms.ErrKeyExists
	}

	_, err = store.client.Logical().Write(fmt.Sprintf("/kv/%s/%s", store.name, key.Name), payload)
	if err != nil {
		return err
	}
	store.cache[key.Name] = key
	return nil
}

func (v *KeyStore) List() []string {
	if v.sealed {
		return []string{}
	}

	v.lock.RLock()
	defer v.lock.RUnlock()

	names := make([]string, 0, len(v.cache))
	for name := range v.cache {
		names = append(names, name)
	}
	return names
}

func (store *KeyStore) Delete(name string) error {
	if store.sealed {
		return kms.ErrSealed
	}

	store.lock.Lock()
	defer store.lock.Unlock()

	_, err := store.client.Logical().Delete(fmt.Sprintf("/kv/%s/%s", store.name, name))
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

func (store *KeyStore) checkStatus(delay time.Duration) {
	for {
		status, err := store.client.Sys().Health()
		if err == nil {
			gotSealed := !store.sealed && status.Sealed
			store.sealed = status.Sealed

			if gotSealed {
				store.lock.Lock()
				store.cache = map[string]kms.Key{}
				store.lock.Unlock()
			}
		}
		time.Sleep(delay)
	}
}

func (store *KeyStore) renewAuthToken(login AppRole, ttl time.Duration) {
	if login.Retry == 0 {
		login.Retry = 15 * time.Second
	}
	for {
		// If Vault is sealed we have to wait
		// until it is unsealed again.
		// The Vault status is checked by another go routine
		// constantly by querying the Vault health status.
		if store.sealed {
			time.Sleep(1 * time.Second)
			continue
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
				time.Sleep(login.Retry)
				continue
			}
			store.client.SetToken(token) // SetToken is safe to call from different go routines
		}

		// Now the client has token with a non-zero TTL
		// such tht we can renew it. We repeat that until
		// the renewable process fails once. In this case
		// we try to re-authenticate again.
		for {
			time.Sleep(ttl / 2)
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
		}
		ttl = 0
	}
}
