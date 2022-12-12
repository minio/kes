// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
	"github.com/minio/kes/internal/secret"
)

// NewSecretFS returns a new SecretFS that
// reads/writes secrets from/to the given
// directory path and en/decrypts them with
// the given encryption key.
func NewSecretFS(filename string, key key.Key) SecretFS {
	return &secretFS{
		rootDir: filename,
		rootKey: key,
	}
}

type secretFS struct {
	rootDir string
	rootKey key.Key
}

func (fs *secretFS) CreateSecret(_ context.Context, name string, secret secret.Secret) error {
	if err := valid(name); err != nil {
		return err
	}
	plaintext, err := secret.MarshalBinary()
	if err != nil {
		return err
	}

	filename := filepath.Join(fs.rootDir, name)
	err = createFile(filename, fs.rootKey, plaintext, []byte(name))
	if errors.Is(err, os.ErrExist) {
		return kes.ErrSecretExists
	}
	if err != nil {
		os.Remove(filename)
	}
	return err
}

func (fs *secretFS) GetSecret(_ context.Context, name string) (sec secret.Secret, err error) {
	if err = valid(name); err != nil {
		return sec, err
	}

	filename := filepath.Join(fs.rootDir, name)
	plaintext, err := readFile(filename, fs.rootKey, secret.MaxSize, []byte(name))
	if errors.Is(err, os.ErrNotExist) {
		return sec, kes.ErrSecretNotFound
	}
	if err != nil {
		return sec, err
	}

	if err = sec.UnmarshalBinary(plaintext); err != nil {
		return sec, err
	}
	return sec, nil
}

func (fs *secretFS) DeleteSecret(_ context.Context, name string) error {
	if err := valid(name); err != nil {
		return err
	}

	err := os.Remove(filepath.Join(fs.rootDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return kes.ErrSecretNotFound
	}
	return err
}

func (fs *secretFS) ListSecrets(ctx context.Context) (secret.Iter, error) {
	file, err := os.Open(fs.rootDir)
	if err != nil {
		return nil, err
	}
	return &iter{
		ctx:  ctx,
		file: file,
	}, nil
}
