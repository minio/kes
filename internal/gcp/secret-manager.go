// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"context"
	"errors"
	"log"
	"path"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// SecretManager is a GCP SecretManager client.
type SecretManager struct {
	client *secretmanager.Client
	config *Config
}

var _ key.Store = (*SecretManager)(nil) // compiler check

// Connect connects and authenticates to a GCP SecretManager
// server.
func Connect(ctx context.Context, c *Config) (*SecretManager, error) {
	c = c.Clone()
	if c == nil {
		c = &Config{}
	}
	c.setDefaults()

	var options = []option.ClientOption{
		option.WithEndpoint(c.Endpoint),
	}
	// We only pass credentials to the GCP client if they
	// are not empty. When running inside GCP, e.g. on app engine,
	// then the GCP credentials are provided by the environment and
	// the GCP SDK will pick them up automatically. In this case
	// the user does not have to provide login credentials at all.
	var empty = Credentials{}
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

	client, err := secretmanager.NewClient(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &SecretManager{
		client: client,
		config: c,
	}, nil
}

// Status returns the current state of the GCP SecretManager instance.
// In particular, whether it is reachable and the network latency.
func (s *SecretManager) Status(ctx context.Context) (key.StoreState, error) {
	state, err := key.DialStore(ctx, s.config.Endpoint)
	if err != nil {
		return key.StoreState{}, err
	}
	if state.State == key.StoreReachable {
		state.State = key.StoreAvailable
	}
	return state, nil
}

// Create stores the given key-value pair at GCP secret manager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// Creating a secret at the GCP SecretManager requires first creating
// secret itself and then adding a secret version with some payload
// data. The payload data contains the actual value.
func (s *SecretManager) Create(ctx context.Context, name string, key key.Key) error {
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
		if grpc.Code(err) == codes.AlreadyExists {
			return kes.ErrKeyExists
		}
		if !errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to create %q: %v", name, err)
		}
		return err
	}

	_, err = s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(key.String()),
		},
	})
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to create %q: %v", name, err)
		}
		return err
	}
	return nil
}

// Get returns the value associated with the given key.
func (s *SecretManager) Get(ctx context.Context, name string) (key.Key, error) {
	result, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: path.Join("projects", s.config.ProjectID, "secrets", name, "versions", "1"),
	})
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			return key.Key{}, kes.ErrKeyNotFound
		}
		if !errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to read %q: %v", name, err)
		}
		return key.Key{}, err
	}

	k, err := key.Parse(string(result.Payload.Data))
	if err != nil {
		s.logf("gcp: failed to parse key %q: %v", name, err)
		return key.Key{}, err
	}
	return k, nil
}

// Delete remove the key-value pair from GCP SecretManager.
//
// Delete will remove all versions of the GCP secret. Even
// though CreateKey will create only one version and fails
// if the secret already exists a user may create more secrets
// versions through e.g. the GCP CLI. However, KES does not
// support multiple secret versions and expects a different
// mechanism for "key-rotation".
func (s *SecretManager) Delete(ctx context.Context, name string) error {
	err := s.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: path.Join("projects", s.config.ProjectID, "secrets", name),
	})
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			return nil
		}
		if errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to delete %q: %v", name, err)
		}
		return err
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *SecretManager) List(ctx context.Context) (key.Iterator, error) {
	var location = path.Join("projects", s.config.ProjectID, "*")
	return &iterator{
		src: s.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
			Parent: location,
		}),
		errHandler: func(err error) {
			s.logf("gcp: failed to list %q: %v", location, err)
		},
	}, nil
}

func (s *SecretManager) logf(format string, v ...interface{}) {
	if s.config.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.config.ErrorLog.Printf(format, v...)
	}
}
