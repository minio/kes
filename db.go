// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"errors"
	"net/http"
	"path"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/crypto"
	"github.com/minio/kes/internal/msgp"
	bolt "go.etcd.io/bbolt"
)

const (
	dbClusterBucket   = "cluster"
	dbEnclaveBucket   = "enclave"
	dbSecretKeyBucket = "key"
	dbSecretBucket    = "secret"
	dbPolicyBucket    = "policy"
	dbIdentityBucket  = "identity"
)

const (
	dbCommitKey      = "commit"
	dbEnclaveKey     = ".enclave"
	dbClusterRootKey = "root"
)

func writeCommit(tx *bolt.Tx, rootKey crypto.SecretKey, commit commit) error {
	b, err := tx.CreateBucketIfNotExists([]byte(dbClusterBucket))
	if err != nil {
		return err
	}
	plaintext, err := msgp.Marshal(&commit)
	if err != nil {
		return err
	}

	associatedData := []byte(dbClusterBucket + "/" + dbCommitKey)
	ciphertext, err := rootKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(dbCommitKey), ciphertext)
}

func createEnclave(tx *bolt.Tx, rootKey crypto.SecretKey, name string, enclave *Enclave) error {
	b, err := tx.CreateBucketIfNotExists([]byte(dbEnclaveBucket))
	if err != nil {
		return err
	}
	b, err = b.CreateBucket([]byte(name))
	if err != nil {
		if errors.Is(err, bolt.ErrBucketExists) {
			return kes.ErrEnclaveExists
		}
		return err
	}

	plaintext, err := msgp.Marshal(enclave)
	if err != nil {
		return err
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, name, dbEnclaveKey))

	ciphertext, err := rootKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(dbEnclaveKey), ciphertext)
}

func readEnclave(tx *bolt.Tx, rootKey crypto.SecretKey, enclave string) (*Enclave, error) {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	ciphertext := bytes.Clone(b.Get([]byte(dbEnclaveKey)))
	if ciphertext == nil {
		// TODO: log a debug / error message.
		// The enclave bucket exists but no enclave metadata found.
		return nil, kes.ErrEnclaveNotFound
	}

	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbEnclaveKey))
	plaintext, err := rootKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	var enc Enclave
	if err = msgp.Unmarshal(plaintext, &enc); err != nil {
		return nil, err
	}
	return &enc, nil
}

func deleteEnclave(tx *bolt.Tx, enclave string) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	return b.DeleteBucket([]byte(enclave))
}

func createSecretKeyRing(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string, ring *crypto.SecretKeyRing) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	b, err := b.CreateBucketIfNotExists([]byte(dbSecretKeyBucket))
	if err != nil {
		return err
	}
	if b.Get([]byte(name)) != nil {
		return kes.ErrKeyExists
	}

	plaintext, err := msgp.Marshal(ring)
	if err != nil {
		return err
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbSecretKeyBucket, name))

	ciphertext, err := enclaveKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(name), ciphertext)
}

func readSecretKeyRing(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string) (*crypto.SecretKeyRing, error) {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbSecretKeyBucket)); b == nil {
		return nil, kes.ErrKeyNotFound
	}
	ciphertext := bytes.Clone(b.Get([]byte(name)))
	if ciphertext == nil {
		return nil, kes.ErrKeyNotFound
	}

	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbSecretKeyBucket, name))
	plaintext, err := enclaveKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	var ring crypto.SecretKeyRing
	if err = msgp.Unmarshal(plaintext, &ring); err != nil {
		return nil, err
	}
	return &ring, nil
}

func deleteSecretKeyRing(tx *bolt.Tx, enclave, name string) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbSecretKeyBucket)); b == nil {
		return nil
	}
	return b.Delete([]byte(name))
}

func createPolicy(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string, policy *auth.Policy) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	b = b.Bucket([]byte(enclave))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	b, err := b.CreateBucketIfNotExists([]byte(dbPolicyBucket))
	if err != nil {
		return err
	}
	if b.Get([]byte(name)) != nil {
		return kes.ErrPolicyExists
	}

	plaintext, err := msgp.Marshal(policy)
	if err != nil {
		return err
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbPolicyBucket, name))

	ciphertext, err := enclaveKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(name), ciphertext)
}

func readPolicy(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string) (*auth.Policy, error) {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbPolicyBucket)); b == nil {
		return nil, kes.ErrPolicyNotFound
	}
	ciphertext := bytes.Clone(b.Get([]byte(name)))
	if ciphertext == nil {
		return nil, kes.ErrPolicyNotFound
	}

	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbPolicyBucket, name))
	plaintext, err := enclaveKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	var policy auth.Policy
	if err = msgp.Unmarshal(plaintext, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func deletePolicy(tx *bolt.Tx, enclave, name string) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbPolicyBucket)); b == nil {
		return kes.ErrPolicyNotFound
	}
	return b.Delete([]byte(name))
}

func createIdentity(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave string, identity kes.Identity, info *auth.Identity) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	b, err := b.CreateBucketIfNotExists([]byte(dbIdentityBucket))
	if err != nil {
		return err
	}
	if b.Get([]byte(identity.String())) != nil {
		return kes.ErrIdentityExists
	}

	parent := bytes.Clone(b.Get([]byte(info.CreatedBy)))
	if parent != nil {
		associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbIdentityBucket, info.CreatedBy.String()))
		plaintext, err := enclaveKey.Decrypt(parent, associatedData)
		if err != nil {
			return err
		}
		var parentInfo auth.Identity
		if err = msgp.Unmarshal(plaintext, &parentInfo); err != nil {
			return err
		}
		if info.IsAdmin && !parentInfo.IsAdmin {
			return kes.NewError(http.StatusForbidden, "insufficient permissions to create admin identity")
		}
		if !info.IsAdmin && info.Policy != "" && !parentInfo.IsAdmin && parentInfo.Policy != "" {
			policy, err := readPolicy(tx, enclaveKey, enclave, info.Policy)
			if err != nil {
				return err
			}
			parentPolicy, err := readPolicy(tx, enclaveKey, enclave, parentInfo.Policy)
			if err != nil {
				return err
			}
			if !policy.IsSubset(parentPolicy) {
				return kes.NewError(http.StatusForbidden, "policy is not a subset of parent policy")
			}
		}

		if !parentInfo.ExpiresAt.IsZero() {
			if info.ExpiresAt.IsZero() {
				info.ExpiresAt = parentInfo.ExpiresAt
			} else if info.ExpiresAt.After(parentInfo.ExpiresAt) {
				info.ExpiresAt = parentInfo.ExpiresAt
			}
			info.TTL = info.ExpiresAt.Sub(info.CreatedAt)
		}
		parentInfo.Children.Set(identity)

		plaintext, err = msgp.Marshal(&parentInfo)
		if err != nil {
			return err
		}
		ciphertext, err := enclaveKey.Encrypt(plaintext, associatedData)
		if err != nil {
			return err
		}
		if err = b.Put([]byte(info.CreatedBy), ciphertext); err != nil {
			return err
		}
	}

	plaintext, err := msgp.Marshal(info)
	if err != nil {
		return err
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbIdentityBucket, identity.String()))
	ciphertext, err := enclaveKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(identity), ciphertext)
}

func readIdentity(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string) (*auth.Identity, error) {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbIdentityBucket)); b == nil {
		return nil, kes.ErrIdentityNotFound
	}
	ciphertext := bytes.Clone(b.Get([]byte(name)))
	if ciphertext == nil {
		return nil, kes.ErrIdentityNotFound
	}

	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbIdentityBucket, name))
	plaintext, err := enclaveKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	var id auth.Identity
	if err = msgp.Unmarshal(plaintext, &id); err != nil {
		return nil, err
	}
	id.Identity = kes.Identity(name)
	return &id, nil
}

func deleteIdentity(b *bolt.Bucket, enclaveKey crypto.SecretKey, enclave string, identity kes.Identity) error {
	if identity == "" {
		return nil
	}
	ciphertext := bytes.Clone(b.Get([]byte(identity.String())))
	if ciphertext == nil {
		return nil
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbIdentityBucket, identity.String()))
	plaintext, err := enclaveKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return err
	}

	var id auth.Identity
	if err = msgp.Unmarshal(plaintext, &id); err != nil {
		return err
	}
	for child := range id.Children.Elements() {
		if err = deleteIdentity(b, enclaveKey, enclave, child); err != nil {
			return err
		}
	}
	return b.Delete([]byte(identity.String()))
}

func createSecret(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string, secret *crypto.Secret) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	b, err := b.CreateBucketIfNotExists([]byte(dbSecretBucket))
	if err != nil {
		return err
	}
	if b.Get([]byte(name)) != nil {
		return kes.ErrSecretExists
	}

	plaintext, err := msgp.Marshal(secret)
	if err != nil {
		return err
	}
	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbSecretBucket, name))

	ciphertext, err := enclaveKey.Encrypt(plaintext, associatedData)
	if err != nil {
		return err
	}
	return b.Put([]byte(name), ciphertext)
}

func readSecret(tx *bolt.Tx, enclaveKey crypto.SecretKey, enclave, name string) (*crypto.Secret, error) {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return nil, kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbSecretBucket)); b == nil {
		return nil, kes.ErrSecretNotFound
	}
	ciphertext := bytes.Clone(b.Get([]byte(name)))
	if ciphertext == nil {
		return nil, kes.ErrSecretNotFound
	}

	associatedData := []byte(path.Join(dbEnclaveBucket, enclave, dbSecretBucket, name))
	plaintext, err := enclaveKey.Decrypt(ciphertext, associatedData)
	if err != nil {
		return nil, err
	}

	var secret crypto.Secret
	if err = msgp.Unmarshal(plaintext, &secret); err != nil {
		return nil, err
	}
	return &secret, nil
}

func deleteSecret(tx *bolt.Tx, enclave, name string) error {
	b := tx.Bucket([]byte(dbEnclaveBucket))
	if b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(enclave)); b == nil {
		return kes.ErrEnclaveNotFound
	}
	if b = b.Bucket([]byte(dbSecretBucket)); b == nil {
		return nil
	}
	return b.Delete([]byte(name))
}

func listBuckets(bucket *bolt.Bucket, prefix string, n int) ([]string, string) {
	p := []byte(prefix)
	cursor := bucket.Cursor()

	var k, v []byte
	if len(p) == 0 {
		k, v = cursor.First()
	} else {
		k, v = cursor.Seek(p)
	}

	var names []string
	for ; k != nil && bytes.HasPrefix(k, p); k, v = cursor.Next() {
		if v != nil {
			continue
		}

		switch len(names) {
		case 0:
			names = make([]string, 0, n)
		case n:
			return names, string(k)
		}
		names = append(names, string(bytes.Clone(k)))
	}
	return names, ""
}

func listKeys[T ~string](bucket *bolt.Bucket, prefix string, n int) ([]T, string) {
	p := []byte(prefix)
	cursor := bucket.Cursor()

	var k, v []byte
	if len(p) == 0 {
		k, v = cursor.First()
	} else {
		k, v = cursor.Seek(p)
	}

	var names []T
	for ; k != nil && bytes.HasPrefix(k, p); k, v = cursor.Next() {
		if v == nil {
			continue
		}

		switch len(names) {
		case 0:
			names = make([]T, 0, n)
		case n:
			return names, string(k)
		}
		names = append(names, T(bytes.Clone(k)))
	}
	return names, ""
}
