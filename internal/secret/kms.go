// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

// KMS is a key management system that holds a set
// of cryptographic secret keys. The KMS interface
// specifies what operations can be performed with
// these secret keys.
//
// In particularly, a KMS can encrypt a value, i.e.
// a secret, with one of its cryptographic keys and
// returns the encrypted value as ciphertext.
// The ciphertext can then be passed to the KMS
// again - together with the same key name - which
// then tries to decrypt it and returns the plaintext
// on success.
type KMS interface {
	// Encrypt encrypts the given plaintext with the
	// cryptographic key referenced by the given key name.
	// It returns the encrypted plaintext as ciphertext.
	// If the encryption fails Encrypt returns a non-nil
	// error.
	Encrypt(key string, plaintext []byte) (ciphertext []byte, err error)

	// Decrypt tries to decrypt the given ciphertext
	// and returns the secret plaintext on success.
	// If the decryption fails Decrypt returns a non-nil
	// error.
	Decrypt(key string, ciphertext []byte) (plaintext []byte, err error)
}
