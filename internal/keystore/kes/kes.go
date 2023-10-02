// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"time"

	"github.com/minio/kes-go"
	"github.com/minio/kes/internal/https"
	"github.com/minio/kes/kv"
)

// Config is a structure containing configuration
// options for connecting to a KES server.
type Config struct {
	// Endpoints contains one or multiple KES
	// server endpoints.
	//
	// A Conn will automatically load balance
	// between multiple endpoints.
	Endpoints []string

	// Enclave is an optional KES enclave name.
	// If empty, the default enclave is used.
	Enclave string

	// PrivateKey is a path to a file containing
	// a X.509 private key for mTLS authentication.
	PrivateKey string

	// Certificate is a path to a file containing
	// a X.509 certificate for mTLS authentication.
	Certificate string

	// CAPath is an optional path to the root CA
	// certificate(s) used to verify the TLS
	// certificate of the KES server. If empty,
	// the host's root CA set is used.
	CAPath string
}

// Connect connects to a KES server with the given configuration.
func Connect(ctx context.Context, config *Config) (*Store, error) {
	if len(config.Endpoints) == 0 {
		return nil, errors.New("kes: no endpoints provided")
	}
	if config.Certificate == "" {
		return nil, errors.New("kes: no certificate provided")
	}
	if config.PrivateKey == "" {
		return nil, errors.New("kes: no private key provided")
	}

	cert, err := https.CertificateFromFile(config.Certificate, config.PrivateKey, "")
	if err != nil {
		return nil, err
	}
	var rootCAs *x509.CertPool
	if config.CAPath != "" {
		rootCAs, err = https.CertPoolFromFile(config.CAPath)
		if err != nil {
			return nil, err
		}
	}

	store := &Store{
		client: kes.NewClientWithConfig("", &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      rootCAs,
		}),
		enclave: config.Enclave,
	}
	store.client.Endpoints = config.Endpoints

	if _, err := store.Status(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

// Store is a connection to a KES server.
type Store struct {
	client  *kes.Client
	enclave string
}

var _ kv.Store[string, []byte] = (*Store)(nil)

// Status returns the current state of the KES connection.
// I particular, whether it is reachable and the network latency.
func (s *Store) Status(ctx context.Context) (kv.State, error) {
	start := time.Now()
	_, err := s.client.Status(ctx)
	latency := time.Since(start)

	if connErr, ok := kes.IsConnError(err); ok {
		return kv.State{}, &kv.Unreachable{Err: connErr}
	}
	if err != nil {
		return kv.State{}, &kv.Unavailable{Err: err}
	}
	return kv.State{
		Latency: latency,
	}, nil
}

// Create creates the given key-value pair at the KES server
// as a seret if and only no such secret already exists.
// If such an entry already exists it returns kes.ErrKeyExists.
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	enclave := s.client.Enclave(s.enclave)
	err := enclave.CreateSecret(ctx, name, value, nil)
	if errors.Is(err, kes.ErrSecretExists) {
		return kes.ErrKeyExists
	}
	return err
}

// Set creates the given key-value pair at the KES server
// as a seret if and only no such secret already exists.
// If such an entry already exists it returns kes.ErrKeyExists.
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
}

// Get returns the value associated with the given name.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	enclave := s.client.Enclave(s.enclave)
	secret, _, err := enclave.ReadSecret(ctx, name)
	if errors.Is(err, kes.ErrSecretNotFound) {
		return nil, kes.ErrKeyNotFound
	}
	return secret, err
}

// Delete removes a the value associated with the given name
// from KES, if it exists. If no such entry exists it returns
// kes.ErrKeyNotFound.
func (s *Store) Delete(ctx context.Context, name string) error {
	enclave := s.client.Enclave(s.enclave)
	err := enclave.DeleteSecret(ctx, name)
	if errors.Is(err, kes.ErrSecretNotFound) {
		return kes.ErrKeyNotFound
	}
	return err
}

// List returns a new kms.Iter over all stored entries.
func (s *Store) List(ctx context.Context) (kv.Iter[string], error) {
	return &iter{
		ctx: ctx,
		iter: &kes.ListIter[string]{
			NextFunc: s.client.Enclave(s.enclave).ListSecrets,
		},
	}, nil
}

// Close closes the Store.
func (s *Store) Close() error { return nil }

type iter struct {
	ctx  context.Context
	iter *kes.ListIter[string]
	err  error
}

func (i *iter) Next() (string, bool) {
	if i.err != nil {
		return "", false
	}

	next, err := i.iter.Next(i.ctx)
	i.err = err
	return next, err == nil
}

func (i *iter) Close() error {
	if i.err == io.EOF {
		return nil
	}
	return i.err
}
