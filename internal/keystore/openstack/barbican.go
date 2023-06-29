// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package openstack

import (
	"context"
	"net/http"
	"time"

	barbican "github.com/artashesbalabekyan/barbican-sdk-go"
	"github.com/artashesbalabekyan/barbican-sdk-go/client"
	"github.com/artashesbalabekyan/barbican-sdk-go/xhttp"
	"github.com/minio/kes-go"
	"github.com/minio/kes/kv"
)

type Connection struct {
	conn   *client.Connection
	config *xhttp.Config
}

// Connect establishes and returns a Store to a Barbican server
// using the given config.
func Connect(ctx context.Context, config *xhttp.Config) (*Connection, error) {
	client, err := barbican.NewConnection(ctx, config)
	if err != nil {
		return nil, err
	}
	conn := &Connection{
		config: config,
		conn:   client,
	}
	return conn, nil
}

// Status returns the current state of the Barbican instance.
// In particular, whether it is reachable and the network latency.
func (s *Connection) Status(ctx context.Context) (kv.State, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.Endpoint, nil)
	if err != nil {
		return kv.State{}, err
	}

	start := time.Now()
	if _, err = http.DefaultClient.Do(req); err != nil {
		return kv.State{}, &kv.Unreachable{Err: err}
	}
	return kv.State{
		Latency: time.Since(start),
	}, nil
}

func (s *Connection) Create(ctx context.Context, name string, value []byte) error {
	return s.conn.Create(ctx, name, value)
}

// Set stores the given key at Barbican if and only
// if no entry with the given name exists.
//
// If no such entry exists, Create returns kes.ErrKeyExists.
func (s *Connection) Set(ctx context.Context, name string, value []byte) error {
	_, err := s.Get(ctx, name)
	if err == nil {
		return s.Create(ctx, name, value)
	}
	return kes.ErrKeyExists
}

// Delete deletes the key associated with the given name
// from Barbican. It may not return an error if no
// entry for the given name exists.
func (s *Connection) Delete(ctx context.Context, name string) error {
	return s.conn.DeleteSecret(ctx, name)
}

// Get returns the key associated with the given name.
//
// If there is no such entry, Get returns kes.ErrKeyNotFound.
func (s *Connection) Get(ctx context.Context, name string) ([]byte, error) {
	secret, err := s.conn.GetSecretWithPayload(ctx, name)
	if err != nil {
		return nil, err
	}
	return secret.Payload, nil
}

// List returns a new Iterator over the Barbican.
//
// The returned iterator may or may not reflect any
// concurrent changes to the Barbican - i.e.
// creates or deletes. Further, it does not provide any
// ordering guarantees.
func (s *Connection) List(ctx context.Context) (kv.Iter[string], error) {
	return s.conn.ListSecrets(ctx)
}
