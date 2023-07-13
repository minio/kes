// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package openstack

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/keymanager/v1/secrets"
	"github.com/minio/kes-go"
	"github.com/minio/kes/kv"
)

type Connection struct {
	opts   gophercloud.AuthOptions
	client *gophercloud.ServiceClient
}

// Connect establishes and returns a Store to a Barbican server
// using the given config.
func Connect(ctx context.Context, opts gophercloud.AuthOptions, endpointOptions gophercloud.EndpointOpts) (*Connection, error) {
	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		return nil, err
	}

	client, err := openstack.NewKeyManagerV1(provider, endpointOptions)
	if err != nil {
		return nil, err
	}

	return &Connection{
		client: client,
		opts:   opts,
	}, nil
}

// Status returns the current state of the Barbican instance.
// In particular, whether it is reachable and the network latency.
func (s *Connection) Status(ctx context.Context) (kv.State, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opts.IdentityEndpoint, nil)
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
	_, err := s.get(ctx, name)
	if err == nil {
		return kes.ErrKeyExists
	}

	createOpts := secrets.CreateOpts{
		Algorithm:          "aes",
		BitLength:          256,
		Mode:               "cbc",
		Name:               name,
		Payload:            string(value),
		PayloadContentType: "text/plain",
		SecretType:         secrets.OpaqueSecret,
	}

	return secrets.Create(s.client, createOpts).Err
}

// Set stores the given key at Barbican if and only
// if no entry with the given name exists.
//
// If no such entry exists, Create returns kes.ErrKeyExists.
func (s *Connection) Set(ctx context.Context, name string, value []byte) error {
	_, err := s.get(ctx, name)
	if err == nil {
		return s.Create(ctx, name, value)
	}
	return kes.ErrKeyExists
}

// Delete deletes the key associated with the given name
// from Barbican. It may not return an error if no
// entry for the given name exists.
func (s *Connection) Delete(ctx context.Context, name string) error {
	secret, err := s.get(ctx, name)
	if err != nil {
		return err
	}

	id := extractIdFromRef(secret.SecretRef)

	return secrets.Delete(s.client, id).Err
}

// Get returns the key associated with the given name.
//
// If there is no such entry, Get returns kes.ErrKeyNotFound.
func (s *Connection) Get(ctx context.Context, name string) ([]byte, error) {
	secret, err := s.get(ctx, name)
	if err != nil {
		return nil, err
	}

	id := extractIdFromRef(secret.SecretRef)

	return secrets.GetPayload(s.client, id, secrets.GetPayloadOpts{PayloadContentType: "*/*"}).Extract()
}

func (s *Connection) get(ctx context.Context, name string) (*secrets.Secret, error) {
	allPages, err := secrets.List(s.client, secrets.ListOpts{
		Name: name,
		Sort: "created:desc",
	}).AllPages()
	if err != nil {
		return nil, err
	}

	allSecrets, err := secrets.ExtractSecrets(allPages)
	if err != nil {
		return nil, err
	}

	if len(allSecrets) == 0 {
		return nil, kes.ErrKeyNotFound
	}

	id := extractIdFromRef(allSecrets[0].SecretRef)

	return secrets.Get(s.client, id).Extract()
}

func extractIdFromRef(ref string) string {
	splitedRef := strings.Split(ref, "/")
	return splitedRef[len(splitedRef)-1]
}

// List returns a new Iterator over the Barbican.
//
// The returned iterator may or may not reflect any
// concurrent changes to the Barbican - i.e.
// creates or deletes. Further, it does not provide any
// ordering guarantees.
func (s *Connection) List(ctx context.Context) (kv.Iter[string], error) {
	allPages, err := secrets.List(s.client, secrets.ListOpts{}).AllPages()
	if err != nil {
		return nil, err
	}

	allSecrets, err := secrets.ExtractSecrets(allPages)
	if err != nil {
		return nil, err
	}

	mapByNames := make(map[string]struct{}, len(allSecrets))
	for _, v := range allSecrets {
		mapByNames[v.Name] = struct{}{}
	}

	values := make(chan string, len(allSecrets))

	go func() {
		defer close(values)
		for name := range mapByNames {
			values <- name
		}
	}()

	return &iterator{
		ch:  values,
		ctx: ctx,
	}, nil
}
