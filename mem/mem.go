package mem

import (
	"sync"

	"github.com/aead/key"
)

type KeyStore struct {
	lock  sync.RWMutex
	store map[string]key.Secret
}

func (store *KeyStore) Create(name string, secret key.Secret) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if store.store == nil {
		store.store = map[string]key.Secret{}
	}
	if _, ok := store.store[name]; ok {
		return key.ErrKeyExists
	}
	store.store[name] = secret
	return nil
}

func (k *KeyStore) Delete(name string) error {
	k.lock.Lock()
	delete(k.store, name)
	k.lock.Unlock()
	return nil
}

func (store *KeyStore) Get(name string) (key.Secret, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	if store.store == nil {
		return key.Secret{}, key.ErrKeyNotFound
	}
	secret, ok := store.store[name]
	if !ok {
		return secret, key.ErrKeyNotFound
	}
	return secret, nil
}
