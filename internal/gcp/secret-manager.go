// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/key"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	gcpiterator "google.golang.org/api/iterator"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

// Credentials represent GCP service account credentials.
type Credentials struct {
	projectID string // not exported - set by the SecretManager

	// ClientID is the client ID of the GCP service account.
	ClientID string

	// Client is the client email of the GCP service account.
	Client string

	// Key is the private key ID of the GCP service account.
	KeyID string

	// Key is the encoded private key of the GCP service account.
	Key string
}

// MarshalJSON returns a JSON representation of the GCP credentials.
//
// The returned JSON contains extra fields to match the JSON credentials
// returned by GCP. Those additional fields are set to default values.
func (c Credentials) MarshalJSON() ([]byte, error) {
	type CredentialsJSON struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
		ClientID     string `json:"client_id"`

		AuthURI             string `json:"auth_uri"`
		TokenURI            string `json:"token_uri"`
		AuthProviderCertURL string `json:"auth_provider_x509_cert_url"`
		ClientCertURL       string `json:"client_x509_cert_url"`
	}
	return json.Marshal(CredentialsJSON{
		Type:                "service_account",
		ProjectID:           c.projectID,
		PrivateKeyID:        c.KeyID,
		PrivateKey:          c.Key,
		ClientEmail:         c.Client,
		ClientID:            c.ClientID,
		AuthURI:             "https://accounts.google.com/o/oauth2/auth",
		TokenURI:            "https://accounts.google.com/o/oauth2/token",
		AuthProviderCertURL: "https://www.googleapis.com/oauth2/v1/certs",
		ClientCertURL:       "https://www.googleapis.com/robot/v1/metadata/x509/service-account-email",
	})
}

// SecretManager is a secret store that uses a GCP SecretManager
// for storing secrets.
type SecretManager struct {
	// Endpoint is the HTTP endpoint of the GCP SecretManager.
	// The endpoint for the GCP SecretManager is:
	//    secretmanager.googleapis.com:443
	Endpoint string

	// The project ID is a unique, user-assigned ID that can be used by Google APIs.
	// The project ID must be a unique string of 6 to 30 lowercase letters, digits, or hyphens.
	// It must start with a letter, and cannot have a trailing hyphen.
	ProjectID string

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	client *secretmanager.Client
}

var _ key.Store = (*SecretManager)(nil) // compiler check

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Create stores the given key-value pair at GCP secret manager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// Creating a secret at the GCP SecretManager requires first creating
// secret itself and then adding a secret version with some payload
// data. The payload data contains the actual value.
func (s *SecretManager) Create(ctx context.Context, name string, key key.Key) error {
	if s.client == nil {
		s.logf("gcp: no connection to GCP secret manager: %q %q", s.Endpoint, s.ProjectID)
		return errCreateKey
	}

	secret, err := s.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
		Parent:   path.Join("projects", s.ProjectID),
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
		return errCreateKey
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
		return errCreateKey
	}
	return nil
}

// Get returns the value associated with the given key.
func (s *SecretManager) Get(ctx context.Context, name string) (key.Key, error) {
	if s.client == nil {
		s.logf("gcp: no connection to GCP secret manager: %q %q", s.Endpoint, s.ProjectID)
		return key.Key{}, errGetKey
	}

	result, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: path.Join("projects", s.ProjectID, "secrets", name, "versions", "1"),
	})
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			return key.Key{}, kes.ErrKeyNotFound
		}
		if !errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to read %q: %v", name, err)
		}
		return key.Key{}, errGetKey
	}

	k, err := key.Parse(string(result.Payload.Data))
	if err != nil {
		s.logf("gcp: failed to parse key %q: %v", name, err)
		return key.Key{}, errGetKey
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
	if s.client == nil {
		s.logf("gcp: no connection to GCP secret manager: %q %q", s.Endpoint, s.ProjectID)
		return errDeleteKey
	}

	err := s.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: path.Join("projects", s.ProjectID, "secrets", name),
	})
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			return nil
		}
		if errors.Is(err, context.Canceled) {
			s.logf("gcp: failed to delete %q: %v", name, err)
		}
		return errDeleteKey
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *SecretManager) List(ctx context.Context) (key.Iterator, error) {
	if s.client == nil {
		s.logf("gcp: no connection to GCP secret manager: %q %q", s.Endpoint, s.ProjectID)
		return nil, errListKey
	}
	location := path.Join("projects", s.ProjectID, "*")
	return &iterator{
		src: s.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
			Parent: location,
		}),
		errHandler: func(err error) {
			s.logf("gcp: failed to list %q: %v", location, err)
		},
	}, nil
}

type iterator struct {
	src        *secretmanager.SecretIterator
	errHandler func(error)
	last       string
	err        error
}

func (i *iterator) Next() bool {
	v, err := i.src.Next()
	if err == gcpiterator.Done {
		return false
	}
	if err != nil {
		i.errHandler(err)
		i.err = errListKey
		return false
	}
	i.last = v.GetName()
	return true
}

func (i *iterator) Name() string { return i.last }

func (i *iterator) Err() error { return i.err }

// Authenticate tries to auth and connect to GCP secret manager
// using the given credentials.
func (s *SecretManager) Authenticate(credentials Credentials) error {
	var options = []option.ClientOption{
		option.WithEndpoint(s.Endpoint),
	}

	// We only pass credentials to the GCP client if they
	// are not empty. When running inside GCP, e.g. on app engine,
	// then the GCP credentials are provided by the environment and
	// the GCP SDK will pick them up automatically. In this case
	// the user does not have to provide login credentials at all.
	var empty = Credentials{}
	if credentials != empty {
		// We do a sanity check here to ensure that the user
		// actually provided some login credentials. However,
		// if the user provides invalid credentials the GCP
		// client will fail on the first request, not when
		// it is created.
		credentials.projectID = s.ProjectID
		if credentials.projectID == "" {
			return errors.New("gcp: no project ID provided")
		}
		if credentials.Client == "" {
			return errors.New("gcp: no client email provided")
		}
		if credentials.ClientID == "" {
			return errors.New("gcp: no client ID provided")
		}
		if credentials.Key == "" {
			return errors.New("gcp: no client private key provided")
		}
		if credentials.KeyID == "" {
			return errors.New("gcp: no client private key ID provided")
		}

		credentialsJSON, err := credentials.MarshalJSON()
		if err != nil {
			return err
		}
		options = append(options, option.WithCredentialsJSON(credentialsJSON))
	}

	client, err := secretmanager.NewClient(context.Background(), options...)
	if err != nil {
		return err
	}
	s.client = client
	return nil
}

func (s *SecretManager) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}
