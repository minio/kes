// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"io"
	"log"

	"github.com/minio/kes"
)

func ExampleClient_GenerateKey() {
	// First, load the client TLS private key / certificate to
	// authenticate against the KES server.
	const (
		keyFile  = "./root.key"
		certFile = "./root.cert"
	)
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate for client (mTLS) authentication: %v", err)
	}

	// Then, generate a new data encryption key (DEK). The DEK contains a
	// plaintext key as well as a ciphertext version. The ciphertext is the
	// plaintext key encrypted by the KES server with the key named 'keyName'.
	// Only the KES server can decrypt the ciphertext key.
	const (
		endpoint = "https://play.min.io:7373"
		keyName  = "my-key"
	)
	client := kes.NewClient(endpoint, certificate)
	key, err := client.GenerateKey(context.Background(), keyName, nil)
	if err != nil {
		log.Fatalf("Failed to generate a new data encryption key: %v", err)
	}

	// Finally, use AES-GCM to encrypt a short message using the plaintext key.
	// The actual ciphertext, the encrypted key, the nonce and the associated data
	// can be stored on some untrusted location. The ciphertext can only be decrypted
	// by contacting the KES server - once the plaintext key is no longer accessible.
	block, err := aes.NewCipher(key.Plaintext)
	if err != nil {
		log.Fatalf("Failed to create AES instance: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Failed to create AES-GCM instance: %v", err)
	}

	var (
		message        = []byte("Hello World")
		nonce          = mustRandom(rand.Reader, gcm.NonceSize())
		associatedData = []byte("my-file.text")
	)
	ciphertext := gcm.Seal(nil, nonce, message, associatedData)

	// Now store the ciphertext as well as the key.Ciphertext, the nonce
	// and the associatedData. The key.Ciphertext contains the encrypted
	// version of the key used to encrypt the message.
	// It needs to be sent to the KES server to obtain the plaintext key
	// which is needed to decrypt the ciphertext (using the nonce and
	// associatedData) and obtain the message again.
	_, _, _, _ = ciphertext, key.Ciphertext, nonce, associatedData
}

func mustRandom(random io.Reader, size int) []byte {
	v := make([]byte, size)
	if _, err := io.ReadFull(random, v); err != nil {
		panic(err)
	}
	return v
}
