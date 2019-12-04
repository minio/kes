package fs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/aead/key"
)

type KeyStore struct {
	Dir string

	lock  sync.RWMutex
	cache map[string]key.Secret
}

func (store *KeyStore) Create(name string, secret key.Secret) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	if _, ok := store.cache[name]; ok {
		return key.ErrKeyExists
	}

	path := filepath.Join(store.Dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil && os.IsExist(err) {
		return key.ErrKeyExists
	}
	if err != nil {
		return err
	}
	defer file.Close()

	const format = `{"name":"%s","secret":"%s"}`
	encoded := fmt.Sprintf(format, name, base64.StdEncoding.EncodeToString(secret[:]))
	if _, err = io.WriteString(file, encoded); err != nil {
		os.Remove(path)
		return err
	}
	if err = file.Sync(); err != nil { // Ensure that we wrote the secret key to disk
		os.Remove(path)
		return err
	}

	if store.cache == nil {
		store.cache = map[string]key.Secret{}
	}
	store.cache[name] = secret
	return nil
}

func (store *KeyStore) Get(name string) (key.Secret, error) {
	// First check whether a secret key is already cached.
	store.lock.RLock()
	if secret, ok := store.cache[name]; ok {
		store.lock.RUnlock()
		return secret, nil
	}
	store.lock.RUnlock()

	// Since we haven't found the requested secret key in the cache
	// we reach out to the disk to fetch it from there.
	file, err := os.Open(filepath.Join(store.Dir, name))
	if err != nil && os.IsNotExist(err) {
		return key.Secret{}, key.ErrKeyNotFound
	}
	if err != nil {
		return key.Secret{}, err
	}
	defer file.Close()

	var content struct {
		Name   string `json:"name"`
		Secret []byte `json:"secret"`
	}
	if err = json.NewDecoder(file).Decode(&content); err != nil {
		return key.Secret{}, err
	}
	if len(content.Secret) != 256/8 {
		return key.Secret{}, errors.New("fs: malformed secret key")
	}

	// Now add the secret key to the cache to
	// make subsequent calls faster.
	store.lock.Lock()
	defer store.lock.Unlock()

	// First, we have to check that 'name' still does not
	// exist. We should not override the cache on a Get
	// when another call has added/fetched a secret key
	// in between.
	if secret, ok := store.cache[name]; ok {
		return secret, nil
	}

	if store.cache == nil {
		store.cache = map[string]key.Secret{}
	}
	var secret key.Secret
	copy(secret[:], content.Secret)
	store.cache[name] = secret
	return secret, nil
}

func (store *KeyStore) Delete(name string) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	err := os.Remove(filepath.Join(store.Dir, name))
	if err != nil && os.IsNotExist(err) {
		err = nil // Ignore the error if the file does not exist
	}
	delete(store.cache, name)
	return err
}
