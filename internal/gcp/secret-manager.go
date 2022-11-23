// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/minio/kes"
	"github.com/minio/kes/kms"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// Conn is a connection to a GCP SecretManager.
type Conn struct {
	client *secretmanager.Client
	config *Config
}

var _ kms.Conn = (*Conn)(nil) // compiler check

// Connect connects and authenticates to a GCP SecretManager
// server.
func Connect(ctx context.Context, c *Config) (*Conn, error) {
	c = c.Clone()
	if c == nil {
		c = &Config{}
	}

	var options []option.ClientOption
	if c.Endpoint != "" {
		options = append(options, option.WithEndpoint(c.Endpoint))
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
	return &Conn{
		client: client,
		config: c,
	}, nil
}

// Status returns the current state of the GCP SecretManager instance.
// In particular, whether it is reachable and the network latency.
func (c *Conn) Status(ctx context.Context) (kms.State, error) {
	return kms.Dial(ctx, c.config.Endpoint)
}

// Create stores the given key-value pair at GCP secret manager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// Creating a secret at the GCP SecretManager requires first creating
// secret itself and then adding a secret version with some payload
// data. The payload data contains the actual value.
func (c *Conn) Create(ctx context.Context, name string, value []byte) error {
	secret, err := c.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   path.Join("projects", c.config.ProjectID),
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
		if grpc.Code(err) == codes.AlreadyExists {
			return kes.ErrKeyExists
		}
		return fmt.Errorf("gcp: failed to create '%s': %v", name, err)
	}

	_, err = c.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
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

// Get returns the value associated with the given key.
func (c *Conn) Get(ctx context.Context, name string) ([]byte, error) {
	result, err := c.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: path.Join("projects", c.config.ProjectID, "secrets", name, "versions", "1"),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if grpc.Code(err) == codes.NotFound {
			return nil, kes.ErrKeyNotFound
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
func (c *Conn) Delete(ctx context.Context, name string) error {
	err := c.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: path.Join("projects", c.config.ProjectID, "secrets", name),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		if grpc.Code(err) == codes.NotFound {
			return kes.ErrKeyNotFound
		}
		return fmt.Errorf("gcp: failed to delete '%s': %v", name, err)
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (c *Conn) List(ctx context.Context) (kms.Iter, error) {
	location := path.Join("projects", c.config.ProjectID)
	return &iterator{
		src: c.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
			Parent: location,
		}),
	}, nil
}
