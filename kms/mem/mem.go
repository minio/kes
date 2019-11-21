package mem

import (
	"sync"

	"github.com/aead/key/kms"
)

type KeyStore struct {
	lock  sync.RWMutex
	store map[string]kms.Key
}

func (store *KeyStore) Create(key kms.Key) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if store.store == nil {
		store.store = map[string]kms.Key{}
	}
	if _, ok := store.store[key.Name]; ok {
		return kms.ErrKeyExists
	}
	store.store[key.Name] = key.Clone()
	return nil
}

func (k *KeyStore) Delete(name string) error {
	k.lock.Lock()
	delete(k.store, name)
	k.lock.Unlock()
	return nil
}

func (store *KeyStore) Get(name string) (kms.Key, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	if store.store == nil {
		return kms.Key{}, kms.ErrKeyNotFound
	}
	key, ok := store.store[name]
	if !ok {
		return key, kms.ErrKeyNotFound
	}
	return key.Clone(), nil
}
