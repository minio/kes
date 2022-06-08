// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fs

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/cpu"
	"github.com/minio/kes/internal/fips"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
	"github.com/minio/kes/internal/sys"
)

type vault struct {
	path     string
	rootKey  key.Key
	errorLog *log.Logger

	lock     sync.RWMutex
	sealed   bool
	sysAdmin kes.Identity
	enclaves map[string]*sys.Enclave
}

func (v *vault) Seal(context.Context) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.sealed {
		return sys.ErrSealed
	}
	v.sysAdmin = ""
	v.rootKey = key.Key{}
	v.enclaves = map[string]*sys.Enclave{}
	v.sealed = true
	return nil
}

func (v *vault) Unseal(context.Context, ...sys.UnsealKey) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if !v.sealed {
		return nil
	}
	stanzaBytes, err := os.ReadFile(filepath.Join(v.path, ".unseal"))
	if err != nil {
		return err
	}
	var stanza sys.Stanza
	if err = stanza.UnmarshalBinary(stanzaBytes); err != nil {
		return err
	}
	rootKeyBytes, err := sys.UnsealFromEnvironment().Unseal(&stanza)
	if err != nil {
		return err
	}
	var rootKey key.Key
	if err := rootKey.UnmarshalBinary(rootKeyBytes); err != nil {
		return err
	}

	v.rootKey = rootKey
	v.sysAdmin = rootKey.CreatedBy()
	v.enclaves = map[string]*sys.Enclave{}
	v.sealed = false
	return nil
}

func (v *vault) SysAdmin(context.Context) (kes.Identity, error) {
	v.lock.RLock()
	defer v.lock.RUnlock()

	if v.sealed {
		return "", sys.ErrSealed
	}
	return v.sysAdmin, nil
}

func (v *vault) CreateEnclave(ctx context.Context, name string, admin kes.Identity) (*sys.EnclaveInfo, error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.sealed {
		return nil, sys.ErrSealed
	}
	if err := sys.VerifyEnclaveName(name); err != nil {
		return nil, err
	}
	if v.sysAdmin == admin {
		return nil, kes.NewError(http.StatusConflict, "enclave admin cannot be system admin")
	}

	path := filepath.Join(v.path, "enclave", name)
	_, err := os.Stat(path)
	if err == nil {
		return nil, kes.ErrEnclaveExists
	}
	if !errors.Is(err, os.ErrNotExist) {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': %v", name, err)
		return nil, err
	}

	if err = os.MkdirAll(path, 0o755); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': %v", name, err)
		return nil, err
	}

	algorithm := key.AES256_GCM_SHA256
	if !fips.Enabled && !cpu.HasAESGCM() {
		algorithm = key.XCHACHA20_POLY1305
	}
	keyStoreKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create key store key: %v", name, err)
		return nil, err
	}
	policyKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create policy key: %v", name, err)
		return nil, err
	}
	identityKey, err := key.Random(algorithm, v.rootKey.CreatedBy())
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create identity key: %v", name, err)
		return nil, err
	}

	if err = CreateKeyStore(filepath.Join(path, "key")); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create key store: %v", name, err)
		return nil, err
	}
	if err = CreatePolicySet(filepath.Join(path, "policy")); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create policy store: %v", name, err)
		return nil, err
	}
	if err = CreateIdentitySet(filepath.Join(path, "identity"), identityKey, admin); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create identity store: %v", name, err)
		return nil, err
	}

	info := sys.EnclaveInfo{
		Name:        name,
		KeyStoreKey: keyStoreKey,
		PolicyKey:   policyKey,
		IdentityKey: identityKey,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   v.rootKey.CreatedBy(),
	}
	plaintext, err := info.MarshalBinary()
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to encode enclave config: %v", name, err)
		return nil, err
	}
	ciphertext, err := v.rootKey.Wrap(plaintext, []byte(name))
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to encrypt enclave config: %v", name, err)
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(path, ".enclave"), ciphertext, 0o600); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to create enclave '%s': failed to create enclave config: %v", name, err)
		return nil, err
	}
	return &info, nil
}

func (v *vault) GetEnclave(ctx context.Context, name string) (*sys.Enclave, error) {
	v.lock.RLock()
	if v.sealed {
		return nil, sys.ErrSealed
	}
	if enclave, ok := v.enclaves[name]; ok {
		v.lock.RUnlock()
		return enclave, nil
	}
	v.lock.RUnlock()

	v.lock.Lock()
	defer v.lock.Unlock()

	if v.sealed {
		return nil, sys.ErrSealed
	}
	if name == "" {
		name = sys.DefaultEnclaveName
	}
	if err := sys.VerifyEnclaveName(name); err != nil {
		return nil, err
	}

	path := filepath.Join(v.path, "enclave", name)
	ciphertext, err := os.ReadFile(filepath.Join(path, ".enclave"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, kes.ErrEnclaveNotFound
	}
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to get enclave '%s': failed to get enclave config: %v", name, err)
		return nil, err
	}
	plaintext, err := v.rootKey.Unwrap(ciphertext, []byte(name))
	if err != nil {
		return nil, err
	}
	var info sys.EnclaveInfo
	if err := info.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}

	keyStore, err := OpenKeyStore(filepath.Join(path, "key"), info.KeyStoreKey, v.errorLog)
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to get enclave '%s': failed to initialize key store: %v", name, err)
		return nil, err
	}
	policySet, err := OpenPolicySet(filepath.Join(path, "policy"), info.PolicyKey, v.errorLog)
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to get enclave '%s': failed to initialize policy store: %v", name, err)
		return nil, err
	}
	identitySet, err := OpenIdentitySet(filepath.Join(path, "identity"), info.IdentityKey, v.errorLog)
	if err != nil {
		xlog.Printf(v.errorLog, "fs: failed to get enclave '%s': failed to initialize identity store: %v", name, err)
		return nil, err
	}
	enclave := sys.NewEnclave(keyStore, policySet, identitySet)
	v.enclaves[name] = enclave
	return enclave, nil
}

func (v *vault) DeleteEnclave(ctx context.Context, name string) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if v.sealed {
		return sys.ErrSealed
	}
	if err := sys.VerifyEnclaveName(name); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to delete enclave '%s': invalid enclave name: %v", name, err)
		return err
	}

	delete(v.enclaves, name)

	path := filepath.Join(v.path, "enclave", name)
	if err := os.RemoveAll(path); err != nil {
		xlog.Printf(v.errorLog, "fs: failed to delete enclave '%s': failed to remove '%s': %v", name, path, err)
		return err
	}
	return nil
}

func validatePath(name string) error {
	if strings.ContainsRune(name, '/') {
		return errors.New("fs: key name contains path separator")
	}
	if runtime.GOOS == "windows" && strings.ContainsRune(name, '\\') {
		return errors.New("fs: key name contains path separator")
	}
	return nil
}
