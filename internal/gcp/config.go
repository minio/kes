// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"encoding/json"
	"log"
	"sync"
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

type Config struct {
	Endpoint string

	ProjectID string

	Credentials Credentials

	ErrorLog *log.Logger

	lock sync.RWMutex
}

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	return &Config{
		Endpoint:  c.Endpoint,
		ProjectID: c.ProjectID,
		ErrorLog:  c.ErrorLog,
	}
}

func (c *Config) setDefaults() {
	if c.Endpoint == "" {
		c.Endpoint = "secretmanager.googleapis.com:443"
	}
}
