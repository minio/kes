// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/minio/kes"
	kesdk "github.com/minio/kes-go"
	"github.com/minio/kes/internal/keystore"
	gcpiterator "google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// Store is a GCP SecretManager secret store.
type Store struct {
	client *secretmanager.Client
	config *Config
}

// Connect connects and authenticates to a GCP SecretManager
// server.
func Connect(ctx context.Context, c *Config) (*Store, error) {
	c = c.Clone()
	if c == nil {
		c = &Config{}
	}

	var options []option.ClientOption
	if c.Endpoint != "" {
		options = append(options, option.WithEndpoint(c.Endpoint))
	} else {
		const DefaultEndpoint = "https://secretmanager.googleapis.com" // From the GCP SDK
		c.Endpoint = DefaultEndpoint
	}
	// We only pass credentials to the GCP client if they
	// are not empty. When running inside GCP, e.g. on app engine,
	// then the GCP credentials are provided by the environment and
	// the GCP SDK will pick them up automatically. In this case
	// the user does not have to provide login credentials at all.
	empty := Credentials{}
	if c.Credentials != empty {
		// We do a sanity check here to ensure that the user
		// actually provided some login credentials. However,
		// if the user provides invalid credentials the GCP
		// client will fail on the first request, not when
		// it is created.
		if c.Credentials.projectID != c.ProjectID {
			c.Credentials.projectID = c.ProjectID
		}
		if c.Credentials.projectID == "" {
			return nil, errors.New("gcp: no project ID provided")
		}
		if c.Credentials.Client == "" {
			return nil, errors.New("gcp: no client email provided")
		}
		if c.Credentials.ClientID == "" {
			return nil, errors.New("gcp: no client ID provided")
		}
		if c.Credentials.Key == "" {
			return nil, errors.New("gcp: no client private key provided")
		}
		if c.Credentials.KeyID == "" {
			return nil, errors.New("gcp: no client private key ID provided")
		}

		credentialsJSON, err := c.Credentials.MarshalJSON()
		if err != nil {
			return nil, err
		}
		options = append(options, option.WithCredentialsJSON(credentialsJSON))
	}
	if len(c.Scopes) != 0 {
		options = append(options, option.WithScopes(c.Scopes...))
	}

	client, err := secretmanager.NewClient(ctx, options...)
	if err != nil {
		return nil, err
	}

	conn := &Store{
		client: client,
		config: c,
	}
	if _, err = conn.Status(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *Store) String() string { return "GCP SecretManager: Project=" + s.config.ProjectID }

// Status returns the current state of the GCP SecretManager instance.
// In particular, whether it is reachable and the network latency.
func (s *Store) Status(ctx context.Context) (kes.KeyStoreState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.Endpoint, nil)
	if err != nil {
		return kes.KeyStoreState{}, err
	}

	start := time.Now()
	if _, err = http.DefaultClient.Do(req); err != nil {
		return kes.KeyStoreState{}, &keystore.ErrUnreachable{Err: err}
	}
	return kes.KeyStoreState{
		Latency: time.Since(start),
	}, nil
}

// Create stores the given key-value pair at GCP secret manager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// Creating a secret at the GCP SecretManager requires first creating
// secret itself and then adding a secret version with some payload
// data. The payload data contains the actual value.
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	secret, err := s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   path.Join("projects", s.config.ProjectID),
		SecretId: name,
		Secret: &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if status.Code(err) == codes.AlreadyExists {
			return kesdk.ErrKeyExists
		}
		return fmt.Errorf("gcp: failed to create '%s': %v", name, err)
	}

	_, err = s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: value,
		},
	})
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if err != nil {
		return fmt.Errorf("gcp: failed to create '%s': %v", name, err)
	}
	return nil
}

// Set stores the given key-value pair at GCP secret manager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// Creating a secret at the GCP SecretManager requires first creating
// secret itself and then adding a secret version with some payload
// data. The payload data contains the actual value.
func (s *Store) Set(ctx context.Context, name string, value []byte) error {
	return s.Create(ctx, name, value)
}

// Get returns the value associated with the given key.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	result, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: path.Join("projects", s.config.ProjectID, "secrets", name, "versions", "1"),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if status.Code(err) == codes.NotFound {
			return nil, kesdk.ErrKeyNotFound
		}
		return nil, fmt.Errorf("gcp: failed to read '%s': %v", name, err)
	}
	return result.Payload.Data, nil
}

// Delete remove the key-value pair from GCP SecretManager.
//
// Delete will remove all versions of the GCP secret. Even
// though CreateKey will create only one version and fails
// if the secret already exists a user may create more secrets
// versions through e.g. the GCP CLI. However, KES does not
// support multiple secret versions and expects a different
// mechanism for "key-rotation".
func (s *Store) Delete(ctx context.Context, name string) error {
	err := s.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: path.Join("projects", s.config.ProjectID, "secrets", name),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if status.Code(err) == codes.NotFound {
			return kesdk.ErrKeyNotFound
		}
		return fmt.Errorf("gcp: failed to delete '%s': %v", name, err)
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
// List returns the first n key names, that start with the given
// prefix, and the next prefix from which the listing should
// continue.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty.
func (s *Store) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	location := path.Join("projects", s.config.ProjectID)

	iter := s.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: location,
	})

	var names []string
	for resp, err := iter.Next(); err != gcpiterator.Done; resp, err = iter.Next() {
		if err != nil {
			return nil, "", err
		}
		names = append(names, path.Base(resp.GetName()))
	}
	return keystore.List(names, prefix, n)
}

// Close closes the Store.
func (s *Store) Close() error { return nil }
