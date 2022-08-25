// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
)

// NewPolicyFS returns a new PolicyFS that
// reads/writes policies from/to the given
// directory path and en/decrypts them with
// the given encryption key.
func NewPolicyFS(filename string, key key.Key) PolicyFS {
	return &policyFS{
		rootDir: filename,
		rootKey: key,
	}
}

type policyFS struct {
	rootDir string
	rootKey key.Key
}

func (fs *policyFS) SetPolicy(_ context.Context, name string, policy auth.Policy) error {
	if err := valid(name); err != nil {
		return err
	}

	// First, we write the policy to a temporary file.
	// The tmp file name contains a character ('.')
	// that is not allowed for client-specified policy names.
	// Therefore, clients cannot create a policy with the
	// same name.
	// Then we rename this temporary file to the actual
	// policy file in one "atomic" operation.
	const TmpFile = "policy.tmp"
	filename := filepath.Join(fs.rootDir, TmpFile)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()

	plaintext, err := policy.MarshalBinary()
	if err != nil {
		return err
	}
	ciphertext, err := fs.rootKey.Wrap(plaintext, []byte(name))
	if err != nil {
		return err
	}

	n, err := file.Write(ciphertext)
	if err != nil {
		return err
	}
	if n != len(ciphertext) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}

	if err = os.Rename(filename, filepath.Join(fs.rootDir, name)); err != nil {
		os.Remove(filename)
		return err
	}
	return nil
}

func (fs *policyFS) GetPolicy(_ context.Context, name string) (auth.Policy, error) {
	if err := valid(name); err != nil {
		return auth.Policy{}, err
	}

	filename := filepath.Join(fs.rootDir, name)
	file, err := os.Open(filename)
	if errors.Is(err, os.ErrNotExist) {
		return auth.Policy{}, kes.ErrPolicyNotFound
	}
	if err != nil {
		return auth.Policy{}, err
	}
	defer file.Close()

	const MaxSize = 1 << 20
	var ciphertext bytes.Buffer
	if _, err = io.Copy(&ciphertext, io.LimitReader(file, MaxSize)); err != nil {
		return auth.Policy{}, err
	}

	plaintext, err := fs.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		return auth.Policy{}, err
	}
	var policy auth.Policy
	if err = policy.UnmarshalBinary(plaintext); err != nil {
		return auth.Policy{}, err
	}
	return policy, nil
}

func (fs *policyFS) DeletePolicy(_ context.Context, name string) error {
	if err := valid(name); err != nil {
		return err
	}

	err := os.Remove(filepath.Join(fs.rootDir, name))
	if errors.Is(err, os.ErrNotExist) {
		return kes.ErrPolicyNotFound
	}
	return err
}

func (fs *policyFS) ListPolicies(ctx context.Context) (auth.PolicyIterator, error) {
	dir, err := os.Open(fs.rootDir)
	if err != nil {
		return nil, err
	}
	return &policyIterator{
		ctx: ctx,
		dir: dir,
	}, nil
}

type policyIterator struct {
	ctx   context.Context
	dir   *os.File
	names []string
	next  string
	err   error
}

func (i *policyIterator) Next() bool {
	if len(i.names) > 0 {
		i.next, i.names = i.names[0], i.names[1:]
		return true
	}
	if i.err != nil {
		return false
	}

	select {
	case <-i.ctx.Done():
		i.err = i.ctx.Err()
		return false
	default:
	}

	const N = 250
	i.names, i.err = i.dir.Readdirnames(N)
	if i.err != nil && i.err != io.EOF {
		return false
	}
	if len(i.names) == 0 && i.err == io.EOF {
		return false
	}
	i.next, i.names = i.names[0], i.names[1:]
	return true
}

func (i *policyIterator) Name() string { return i.next }

func (i *policyIterator) Close() error {
	if err := i.dir.Close(); i.err == nil || i.err == io.EOF {
		return err
	}
	return i.err
}
