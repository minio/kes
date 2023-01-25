// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
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
	clientCertURL, err := url.JoinPath("https://www.googleapis.com/robot/v1/metadata/x509", url.QueryEscape(c.Client))
	if err != nil {
		return nil, err
	}
	// A single-quoted YAML string ('foo') will represent newline characters as
	// two runes (i.e. a "\" followed by "n"). Typically a private key contains
	// newline characters. Hence, we replace the two rune string "\\n" with the
	// newline character '\n'. Otherwise, the GCP SDK will fail to parse the private
	// key.
	return json.Marshal(CredentialsJSON{
		Type:                "service_account",
		ProjectID:           c.projectID,
		PrivateKeyID:        c.KeyID,
		PrivateKey:          strings.ReplaceAll(c.Key, "\\n", "\n"),
		ClientEmail:         c.Client,
		ClientID:            c.ClientID,
		AuthURI:             "https://accounts.google.com/o/oauth2/auth",
		TokenURI:            "https://accounts.google.com/o/oauth2/token",
		AuthProviderCertURL: "https://www.googleapis.com/oauth2/v1/certs",
		ClientCertURL:       clientCertURL,
	})
}

// Config is a structure containing configuration
// options for connecting to a KeySecure server.
type Config struct {
	// Endpoint is the GCP SecretManager endpoint.
	Endpoint string

	// ProjectID is the ID of the GCP project.
	ProjectID string

	// Credentials are the GCP credentials to
	// access the SecretManager.
	Credentials Credentials

	// Scopes are GCP OAuth2 scopes for accessing GCP APIs.
	// If not set, defaults to the GCP default scopes.
	//
	// Ref: https://developers.google.com/identity/protocols/oauth2/scopes
	Scopes []string

	// ErrorLog is an optional logger for errors
	// that may occur when interacting with GCP
	// SecretManager.
	ErrorLog *log.Logger

	lock sync.RWMutex
}

// Clone returns a shallow clone of c or nil if c is
// nil. It is safe to clone a Config that is being used
// concurrently.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	c.lock.RLock()
	defer c.lock.RUnlock()
	clone := &Config{
		Endpoint:    c.Endpoint,
		ProjectID:   c.ProjectID,
		Credentials: c.Credentials,
		ErrorLog:    c.ErrorLog,
	}
	if len(c.Scopes) > 0 {
		clone.Scopes = make([]string, 0, len(c.Scopes))
		clone.Scopes = append(clone.Scopes, c.Scopes...)
	}
	return clone
}
