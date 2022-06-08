// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package fs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/auth"
	"github.com/minio/kes/internal/key"
	xlog "github.com/minio/kes/internal/log"
)

// CreatePolicySet creates a new auth.PolicySet at the given path.
func CreatePolicySet(path string) error { return os.MkdirAll(path, 0o755) }

// OpenPolicySet opens the auth.PolicySet at the given path.
func OpenPolicySet(path string, key key.Key, errorLog *log.Logger) (auth.PolicySet, error) {
	return &policySet{
		path:     path,
		rootKey:  key,
		errorLog: errorLog,
		policies: map[string]*auth.Policy{},
	}, nil
}

type policySet struct {
	path     string
	rootKey  key.Key
	errorLog *log.Logger

	lock     sync.RWMutex
	policies map[string]*auth.Policy
}

func (p *policySet) Set(ctx context.Context, name string, policy *auth.Policy) error {
	if err := validatePath(name); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': invalid policy name: %v", name, err)
		return err
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	delete(p.policies, name)

	plaintext, err := policy.MarshalBinary()
	if err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to encode policy: %v", name, err)
		return err
	}
	ciphertext, err := p.rootKey.Wrap(plaintext, []byte(name))
	if err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to encrypt policy: %v", name, err)
		return err
	}

	path := filepath.Join(p.path, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to create '%s': %v", name, path, err)
		return err
	}
	defer file.Close()

	if _, err = file.Write(ciphertext); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to write to '%s': %v", name, path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to remove '%s': %v", name, path, rmErr)
		}
		return err
	}
	if err = file.Sync(); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to set policy '%s': fs sync failed: %v", name, err)
		if rmErr := os.Remove(path); rmErr != nil {
			xlog.Printf(p.errorLog, "fs: failed to set policy '%s': failed to remove '%s': %v", name, path, rmErr)
		}
		return err
	}
	return nil
}

func (p *policySet) Delete(ctx context.Context, name string) error {
	if err := validatePath(name); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to delete policy '%s': invalid policy name: %v", name, err)
		return err
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	delete(p.policies, name)

	path := filepath.Join(p.path, name)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return kes.ErrPolicyNotFound
		}
		xlog.Printf(p.errorLog, "fs: failed to delete policy '%s': %v", name, err)
		return err
	}
	return nil
}

func (p *policySet) Get(ctx context.Context, name string) (*auth.Policy, error) {
	if err := validatePath(name); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to get policy '%s': invalid policy name: %v", name, err)
		return nil, err
	}
	p.lock.RLock()
	if policy, ok := p.policies[name]; ok {
		p.lock.RUnlock()
		return policy, nil
	}
	p.lock.RUnlock()

	p.lock.Lock()
	defer p.lock.Unlock()

	path := filepath.Join(p.path, name)
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, kes.ErrPolicyNotFound
		}
		xlog.Printf(p.errorLog, "fs: failed to get policy '%s': failed to open '%s': %v", name, path, err)
		return nil, err
	}
	defer file.Close()

	var ciphertext bytes.Buffer
	if _, err := io.Copy(&ciphertext, io.LimitReader(file, 1<<20)); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to get policy '%s': failed to read from '%s': %v", name, path, err)
		return nil, err
	}
	plaintext, err := p.rootKey.Unwrap(ciphertext.Bytes(), []byte(name))
	if err != nil {
		xlog.Printf(p.errorLog, "fs: failed to get policy '%s': failed to decrypt policy: %v", name, err)
		return nil, err
	}

	var policy auth.Policy
	if err := policy.UnmarshalBinary(plaintext); err != nil {
		xlog.Printf(p.errorLog, "fs: failed to get policy '%s': failed to parse policy: %v", name, err)
		return nil, err
	}
	p.policies[name] = &policy
	return &policy, nil
}

func (p *policySet) List(ctx context.Context) (auth.PolicyIterator, error) {
	dir, err := os.Open(p.path)
	if err != nil {
		xlog.Printf(p.errorLog, "fs: failed to list policies '%v'", err)
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
