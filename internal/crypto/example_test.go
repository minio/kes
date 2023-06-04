// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package crypto_test

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/minio/kes/internal/crypto"
)

func ExampleSecretKey_Encrypt() {
	key, err := crypto.GenerateSecretKey(crypto.AES256, nil)
	if err != nil {
		log.Fatalf("failed to generate AES256 key: %v", err)
	}

	ciphertext, err := key.Encrypt([]byte("Hello World"), nil)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}
	_ = ciphertext
	// Output:
}

func ExampleSecretKey_Decrypt() {
	const (
		KeyBytes        = "8612a2d23764284e0da438de559a3d8162983ab574ec69f95c1aeed6a4e1077d"
		CiphertextBytes = "6a3912cfee99ca51c12004f8fb3ea912b45966f3e5e33cd886993084f9d2c1433028a59231e26f9ec0c1cd2426a97d4cc9988ba968b9b0"
	)

	keyBytes, _ := hex.DecodeString(KeyBytes)
	ciphertext, _ := hex.DecodeString(CiphertextBytes)

	key, err := crypto.NewSecretKey(crypto.AES256, keyBytes)
	if err != nil {
		log.Fatalf("failed to create AES256 key: %v", err)
	}

	plaintext, err := key.Decrypt(ciphertext, nil)
	if err != nil {
		log.Fatalf("failed to decrypt ciphertext: %v", err)
	}
	fmt.Println(string(plaintext))

	// Output:
	// Hello World
}
