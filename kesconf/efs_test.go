// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kesconf_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minio/kes"
	"github.com/minio/kes/kesconf"
)

var EncryptedFSPath = flag.String("efs.path", "", "Path used for EncryptedFS tests")

func TestEncryptedFS(t *testing.T) {
	if *EncryptedFSPath == "" {
		t.Skip("EncryptedFS tests disabled. Use -efs.path=<path> to enable them")
	}

	masterKey := "passwordpasswordpasswordpassword"
	masterKeyPath := filepath.Join(*EncryptedFSPath, "test-master-key")
	masterKeyCipher := "AES256"
	if err := os.WriteFile(masterKeyPath, []byte(masterKey), 0o644); err != nil {
		t.Fatalf("Failed to write master key into test dir")
	}

	config := kesconf.EncryptedFSKeyStore{
		MasterKeyPath:   masterKeyPath,
		MasterKeyCipher: masterKeyCipher,
		Path:            *EncryptedFSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	store, err := config.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Create", func(t *testing.T) { testCreate(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Get", func(t *testing.T) { testGet(ctx, store, t, RandString(ranStringLength)) })
	t.Run("Status", func(t *testing.T) { testStatus(ctx, store, t) })
	t.Run("List", func(t *testing.T) { efsTestList(ctx, store, t) })
	t.Run("BackwardCompatible", func(t *testing.T) { efsTestBackwardCompatible(ctx, store, t, *EncryptedFSPath) })
	t.Run("Encrypted", func(t *testing.T) { efsTestEnsureEncrypted(ctx, store, t, *EncryptedFSPath) })
	t.Run("EncryptionContext", func(t *testing.T) { efsTestEncryptionContext(ctx, store, t, *EncryptedFSPath) })
}

// test all operations
func efsTestList(ctx context.Context, store kes.KeyStore, t *testing.T) {
	defer clean(ctx, store, t)

	// empty kek list
	kekList, _, err := store.List(ctx, "test", 10)
	if err != nil {
		t.Fatalf("Failed to list store: %v", err)
	}
	if len(kekList) != 0 {
		t.Fatalf("Unexpected kek list entries, expected empty list: %d entries", len(kekList))
	}

	// create kek
	kekName := "test-kek"
	kekPlaintext := "my-plaintext-kek"
	err = store.Create(ctx, kekName, []byte(kekPlaintext))
	if err != nil {
		t.Fatalf("Unable to create kek: %v", err)
	}

	// list new kek
	kekList, _, err = store.List(ctx, "test", 10)
	if err != nil {
		t.Fatalf("Failed to list store: %v", err)
	}
	if len(kekList) != 1 {
		t.Fatalf("Unexpected kek list entries, expected list with one entry: %d entries", len(kekList))
	}
	if kekList[0] != kekName {
		t.Fatalf("Unexpected kek list entry: %s", kekList[0])
	}

	// read kek
	decryptetdKek, err := store.Get(ctx, kekName)
	if err != nil {
		t.Fatalf("Failed to read kek: %v", err)
	}
	if !bytes.Equal(decryptetdKek, []byte(kekPlaintext)) {
		t.Fatalf("Failed to decrypt kek: %s vs. %s", string(decryptetdKek), kekPlaintext)
	}

	// delete kek
	err = store.Delete(ctx, kekName)
	if err != nil {
		t.Fatalf("Failed to delete kek: %v", err)
	}

	// empty kek list
	kekList, _, err = store.List(ctx, "test", 10)
	if err != nil {
		t.Fatalf("Failed to list store: %v", err)
	}
	if len(kekList) != 0 {
		t.Fatalf("Unexpected kek list entries, expected empty list: %d entries", len(kekList))
	}
}

// ensure backward compatibility: read a known encrypted kek
func efsTestBackwardCompatible(ctx context.Context, store kes.KeyStore, t *testing.T, tmp string) {
	defer clean(ctx, store, t)

	// write encrypted kek to disk
	kekName := "test-kek"
	kekPlaintext := "my-plaintext-kek"
	encrypetdKek, err := base64.StdEncoding.DecodeString("Eu4t1j1T8CuLjgxqZoCBXguh6DJ+Jg4oZyhPUE6CNsgeGGZ3UhxQ0Eozh1A0THfsx/EK9rc97V2RTg5U")
	if err != nil {
		t.Fatalf("Failed to decode encrypted kek base64: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, kekName), encrypetdKek, 0o644); err != nil {
		t.Fatalf("Failed to write encrypted key into test temp dir")
	}

	// read kek
	decryptetdKek, err := store.Get(ctx, kekName)
	if err != nil {
		t.Fatalf("Failed to read kek: %v", err)
	}
	if !bytes.Equal(decryptetdKek, []byte(kekPlaintext)) {
		t.Fatalf("Failed to decrypt kek: %s vs. %s", string(decryptetdKek), kekPlaintext)
	}
}

// basic test to ensure kek was not written in plaintext to disk
func efsTestEnsureEncrypted(ctx context.Context, store kes.KeyStore, t *testing.T, tmp string) {
	defer clean(ctx, store, t)

	// create kek
	kekName := "test-kek"
	kekPlaintext := "my-plaintext-kek"
	err := store.Create(ctx, kekName, []byte(kekPlaintext))
	if err != nil {
		t.Fatalf("Unable to create kek: %v", err)
	}

	// ensure file on disk does not contain plaintext kek
	fileContent, err := os.ReadFile(filepath.Join(tmp, kekName))
	if err != nil {
		t.Fatalf("Failed to read kek file: %v", err)
	}
	if bytes.Equal(fileContent, []byte(kekPlaintext)) {
		t.Fatalf("Content of kek file not encrypted")
	}
}

// test key context gets validated
func efsTestEncryptionContext(ctx context.Context, store kes.KeyStore, t *testing.T, tmp string) {
	defer clean(ctx, store, t)

	// create kek
	kekName := "test-kek"
	kekPlaintext := "my-plaintext-kek"
	err := store.Create(ctx, kekName, []byte(kekPlaintext))
	if err != nil {
		t.Fatalf("Unable to create kek: %v", err)
	}

	// copy kek
	otherKekName := "other-kek"
	fileContent, err := os.ReadFile(filepath.Join(tmp, kekName))
	if err != nil {
		t.Fatalf("Failed to read encrypted kek file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, otherKekName), fileContent, 0o644); err != nil {
		t.Fatalf("Failed to write encrypted kek into new file: %v", err)
	}

	// read other kek
	_, err = store.Get(ctx, otherKekName)
	if err == nil || !strings.Contains(fmt.Sprint(err), "ciphertext is not authentic") {
		t.Fatalf("Expected get to fail with ciphertext is not authentic")
	}
}

// test keystore init fails if master key is missing
func TestEncryptedFSmissingMasterKey(t *testing.T) {
	if *EncryptedFSPath == "" {
		t.Skip("EncryptedFS tests disabled. Use -efs.path=<path> to enable them")
	}

	// missing master key
	config := kesconf.EncryptedFSKeyStore{
		MasterKeyPath:   filepath.Join(*EncryptedFSPath, "master-key"),
		MasterKeyCipher: "AES256",
		Path:            *EncryptedFSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	// init keystore fails
	_, err := config.Connect(ctx)
	if err == nil {
		t.Fatalf("Expected init to fail on missing master key")
	}
}

// test keystore init fails if master key has unknown length
func TestEncryptedFSinvalidMasterKeyLengthToShort(t *testing.T) {
	if *EncryptedFSPath == "" {
		t.Skip("EncryptedFS tests disabled. Use -efs.path=<path> to enable them")
	}

	// create master key with invalid length
	masterKey := "veryshortkey"
	masterKeyCipher := "AES256"
	masterKeyPath := filepath.Join(*EncryptedFSPath, "master-key")
	if err := os.WriteFile(masterKeyPath, []byte(masterKey), 0o644); err != nil {
		t.Fatalf("Failed to write master key into test temp dir")
	}
	defer os.Remove(masterKeyPath)

	config := kesconf.EncryptedFSKeyStore{
		MasterKeyPath:   masterKeyPath,
		MasterKeyCipher: masterKeyCipher,
		Path:            *EncryptedFSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	// init keystore fails
	_, err := config.Connect(ctx)
	if err == nil {
		t.Fatalf("Expected init to fail on invalid master key length")
	}
}

// test keystore init fails if master key has unknown length
func TestEncryptedFSinvalidMasterKeyLengthToLarge(t *testing.T) {
	if *EncryptedFSPath == "" {
		t.Skip("EncryptedFS tests disabled. Use -efs.path=<path> to enable them")
	}

	// create master key with invalid length
	masterKey := "verylongverylongverylongverylongverylongverylongverylongverylong"
	masterKeyCipher := "AES256"
	masterKeyPath := filepath.Join(*EncryptedFSPath, "master-key")
	if err := os.WriteFile(masterKeyPath, []byte(masterKey), 0o644); err != nil {
		t.Fatalf("Failed to write master key into test temp dir")
	}
	defer os.Remove(masterKeyPath)

	config := kesconf.EncryptedFSKeyStore{
		MasterKeyPath:   masterKeyPath,
		MasterKeyCipher: masterKeyCipher,
		Path:            *EncryptedFSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	// init keystore fails
	_, err := config.Connect(ctx)
	if err == nil {
		t.Fatalf("Expected init to fail on invalid master key length")
	}
}

// test keystore init fails on unknown cipher
func TestEncryptedFSunknownMasterKeyCipher(t *testing.T) {
	if *EncryptedFSPath == "" {
		t.Skip("EncryptedFS tests disabled. Use -efs.path=<path> to enable them")
	}

	// create master key with unknown cipher
	masterKey := "passwordpasswordpasswordpassword"
	masterKeyCipher := "UNKNOWN"
	masterKeyPath := filepath.Join(*EncryptedFSPath, "master-key")
	if err := os.WriteFile(masterKeyPath, []byte(masterKey), 0o644); err != nil {
		t.Fatalf("Failed to write master key into test temp dir")
	}
	defer os.Remove(masterKeyPath)

	config := kesconf.EncryptedFSKeyStore{
		MasterKeyPath:   masterKeyPath,
		MasterKeyCipher: masterKeyCipher,
		Path:            *EncryptedFSPath,
	}

	ctx, cancel := testingContext(t)
	defer cancel()

	// init keystore fails
	_, err := config.Connect(ctx)
	if err == nil {
		t.Fatalf("Expected init to fail on unknown master key cipher")
	}
}
