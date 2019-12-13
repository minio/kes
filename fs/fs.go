// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

// Package fs implements a secret key store that
// stores secret keys as files on the file system.
package fs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
)

// KeyStore is a file system secret key store
// that stores secret keys as files in a directory.
type KeyStore struct {
	// Dir is the directory where secret key files
	// are located. The key store will read / write
	// secrets from / to files in this directory.
	Dir string

	// CacheExpireAfter is the duration after which
	// cache entries expire such that they have to
	// be loaded from the backend storage again.
	CacheExpireAfter time.Duration

	// CacheExpireUnusedAfter is the duration after
	// which not recently used cache entries expire
	// such that they have to be loaded from the
	// backend storage again.
	// Not recently is defined as: CacheExpireUnusedAfter / 2
	CacheExpireUnusedAfter time.Duration

	cache cache.Cache
	once  uint32
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
//
// In particular, Create creates a new file in KeyStore.Dir
// and writes the secret key to it.
func (store *KeyStore) Create(name string, secret kes.Secret) error {
	store.initialize()
	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
	}

	path := filepath.Join(store.Dir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil && os.IsExist(err) {
		return kes.ErrKeyExists
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

	store.cache.Set(name, secret)
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the associated
// file in KeyStore.Dir.
func (store *KeyStore) Get(name string) (kes.Secret, error) {
	store.initialize()
	if secret, ok := store.cache.Get(name); ok {
		return secret, nil
	}

	// Since we haven't found the requested secret key in the cache
	// we reach out to the disk to fetch it from there.
	file, err := os.Open(filepath.Join(store.Dir, name))
	if err != nil && os.IsNotExist(err) {
		return kes.Secret{}, kes.ErrKeyNotFound
	}
	if err != nil {
		return kes.Secret{}, err
	}
	defer file.Close()

	var content struct {
		Name   string `json:"name"`
		Secret []byte `json:"secret"`
	}
	if err = json.NewDecoder(file).Decode(&content); err != nil {
		return kes.Secret{}, err
	}
	if len(content.Secret) != 256/8 {
		return kes.Secret{}, errors.New("fs: malformed secret key")
	}

	var secret kes.Secret
	copy(secret[:], content.Secret)
	secret, _ = store.cache.Add(name, secret)
	return secret, nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the associated file,
// if it exists.
func (store *KeyStore) Delete(name string) error {
	err := os.Remove(filepath.Join(store.Dir, name))
	if err != nil && os.IsNotExist(err) {
		err = nil // Ignore the error if the file does not exist
	}
	store.cache.Delete(name)
	return err
}

func (store *KeyStore) initialize() {
	if atomic.CompareAndSwapUint32(&store.once, 0, 1) {
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}
