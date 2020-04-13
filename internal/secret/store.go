// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/secure-io/sio-go/sioutil"
)

// MaxSize is the max. size of a (encrypted) secret.
//
// Neither a secret nor an encrypted secret should
// be larger than 1 MiB.
//
// Implementions of Remote should use this to limit
// the amount of data they read from the key-value
// store.
const MaxSize = 1 << 20 // 1 MiB

// Remote is a key-value store for plain or
// encrypted secrets. Therefore, it stores
// keys and values as strings.
//
// Remote is the interface that must be
// implemented by secret store backends,
// like Vault or AWS SecretsManager.
type Remote interface {
	// Create adds the given key-value pair to
	// the remote store if and only if no entry
	// for the given key exists already.
	//
	// If key already exists at the remote store
	// it does not replace the secret and returns
	// kes.ErrKeyExists.
	//
	// Create returns the first error it encounters
	// while trying to add the given key-value pair
	// to the store, if any.
	Create(key string, value string) error

	// Delete deletes the given key and the associated
	// value from the remote store. It does not return
	// an non-nil error if the key does not exist.
	//
	// Delete returns the first error it encounters
	// while trying to delete the given key from the
	// store, if any.
	Delete(key string) error

	// Get returns the value associated with the given
	// key. If no value is associated with key then Get
	// returns kes.ErrKeyNotFound.
	//
	// Get returns the first error it encounters while
	// trying to add the given key-value pair to the
	// store, if any.
	Get(key string) (value string, err error)
}

// Store is the local secret store connected
// to a remote key-value store.
//
// It is responsible for en/decrypting secrets
// if a KMS is present and for caching secrets
// fetched from the remote key value store.
type Store struct {
	// Key is the name of the cryptographic key
	// at the KMS used to encrypt newly created
	// secrets before sending them to the remote
	// key-value store.
	//
	// If KMS is nil it will be ignored.
	// It must not be modified once the Store
	// has been used to fetch or store secrets.
	Key string

	// KMS is the KMS implementation used to
	// encrypt secrets before sending them to
	// the remote key-value store.
	//
	// It uses the Store.Key as the default
	// cryptographic key for encrypting new
	// secrets
	//
	// If the KMS is nil then all newly created
	// secrets will be stored as plaintext.
	//
	// If KMS is present and the remote key-value
	// store returns a plaintext value then the
	// Store still tries to decrypt the plaintext
	// value - which should fail.
	// Similarly, if no KMS is present and the
	// remote key-value store returns an encrypted
	// value then the Store does not try to decrypt
	// the value.
	// Basically, the remote store must return only
	// plaintext values or ciphertext values - but
	// not both.
	//
	// It must not be modified once the Store has been
	// used to fetch or store secrets.
	KMS KMS

	// Remote is the remote key-value store. Secrets
	// will be fetched from or written to this store.
	//
	// It must not be modified once the Store has been
	// used to fetch or store secrets.
	Remote Remote

	cache cache
	once  sync.Once // For the cache garbage collection
}

// Create adds the given secret with the given name to
// the secret store. If there is already a secret with
// this name then it does not replacce the secret and
// returns kes.ErrKeyExists.
func (s *Store) Create(name string, secret Secret) (err error) {
	var value string
	if s.KMS != nil {
		value, err = s.encrypt(secret)
		if err != nil {
			return err
		}
	} else {
		value = secret.String()
	}

	if err = s.Remote.Create(name, value); err != nil {
		return err
	}
	s.cache.SetOrGet(name, secret)
	return nil
}

// Delete deletes the secret associated with the given
// name, if one exists.
func (s *Store) Delete(name string) error {
	// We can always remove a secret from the cache.
	// If the delete operation on the remote store
	// fails we will fetch it again on the next Get.
	s.cache.Delete(name)
	return s.Remote.Delete(name)
}

// Get returns the secret associated with the given name,
// if any. If no such secret exists it returns
// kes.ErrKeyNotFound.
func (s *Store) Get(name string) (Secret, error) {
	if secret, ok := s.cache.Get(name); ok {
		return secret, nil
	}

	value, err := s.Remote.Get(name)
	if err != nil {
		return Secret{}, err
	}

	var secret Secret
	if s.KMS != nil {
		secret, err = s.decrypt(value)
		if err != nil {
			return Secret{}, err
		}
	} else {
		if err = secret.ParseString(value); err != nil {
			return Secret{}, err
		}
	}
	return s.cache.SetOrGet(name, secret), nil
}

// StartGC starts the cache garbage collection background process.
// The GC will discard all cached secrets after expiry. Further,
// it will discard all entries that havn't been used for unusedExpiry.
//
// If expiry is 0 the GC will not discard any secrets. Similarly, if
// the unusedExpiry is 0 then the GC will not discard unused secrets.
//
// There is only one garbage collection background process. Calling
// StartGC more than once has no effect.
func (s *Store) StartGC(ctx context.Context, expiry, unusedExpiry time.Duration) {
	s.once.Do(func() {
		s.cache.StartGC(ctx, expiry)

		// Actually, we also don't run the unused GC if unusedExpiry/2 == 0,
		// not if unusedExpiry == 0.
		// However, that can only happen if unusedExpiry is 1ns - which is
		// anyway an unreasonable value for the expiry.
		s.cache.StartUnusedGC(ctx, unusedExpiry/2)
	})
}

// encrypt encrypts the given secret with the Store.KMS
// and returns the string representation of the ciphertext.
//
// More specifically, encrypt first encrypts the secret
// with a randomly generated secret key. The result of
// this first encryption gets then passed to the KMS -
// which performs a second encryption with the key
// referenced by Store.Key.
//
// This two-stage encryption process ensures that one the
// one hand access to the KMS is necessary to decrypt the
// secret again and on the other hand the KMS provider is
// not able to learn the plaintext secrets.
// If we would not encrypt the secret *before* sending it
// to the KMS then whoever can observe/inspect the KMS can
// sees our secrets in plaintext.
//
// The randomly generated secret key for the first encryption
// stage is embedded into the returned ciphertext string.
func (s *Store) encrypt(secret Secret) (string, error) {
	var localKey Secret
	random, err := sioutil.Random(len(localKey))
	if err != nil {
		return "", err
	}
	copy(localKey[:], random)

	bytes, err := localKey.Wrap([]byte(secret.String()), []byte(s.Key))
	if err != nil {
		return "", err
	}
	bytes, err = s.KMS.Encrypt(s.Key, bytes)
	if err != nil {
		return "", err
	}

	type Ciphertext struct {
		LocalKey Secret `json:"local_key"`

		KeyName string `json:"kms_key"`
		Bytes   []byte `json:"ciphertext"`
	}
	ciphertext, err := json.Marshal(Ciphertext{
		LocalKey: localKey,
		KeyName:  s.Key,
		Bytes:    bytes,
	})
	if err != nil {
		return "", err
	}
	return string(ciphertext), nil
}

// decrypt tries to decrypt the given string representation
// of an encrypted secret with the Store.KMS and returns the
// plaintext secret on success.
//
// Therefore, it parses the given ciphertext string, decrypts
// the actual ciphertext bytes using the KMS and then uses the
// local key (part of the ciphertext string) to decrypt the
// response from the KMS.
// See: encrypt for more details about this two-stage process.
func (s *Store) decrypt(ciphertext string) (Secret, error) {
	type Ciphertext struct {
		LocalKey Secret `json:"local_key"`

		KeyName string `json:"kms_key"`
		Bytes   []byte `json:"ciphertext"`
	}

	var ctxt Ciphertext
	if err := json.Unmarshal([]byte(ciphertext), &ctxt); err != nil {
		return Secret{}, err
	}

	plaintext, err := s.KMS.Decrypt(ctxt.KeyName, ctxt.Bytes)
	if err != nil {
		return Secret{}, err
	}
	plaintext, err = ctxt.LocalKey.Unwrap(plaintext, []byte(ctxt.KeyName))
	if err != nil {
		return Secret{}, err
	}

	var secret Secret
	if err = secret.ParseString(string(plaintext)); err != nil {
		return Secret{}, err
	}
	return secret, nil
}
