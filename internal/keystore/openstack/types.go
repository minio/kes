// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package openstack

type Credentials struct {
	ProjectDomain  string
	ProjectName    string
	AuthUrl        string
	Username       string
	Password       string
	UserDomainName string
}

// Config is a structure containing configuration
// options for connecting to a Barbican server.
type Config struct {
	// Endpoint is the Barbican instance endpoint.
	Endpoint string

	// Credentials used to login to OpenStack to retrieve the APIKey
	Login Credentials
}

type Connection struct {
	config Config
	client *client
}

type BarbicanSecretsResponse struct {
	Next     string           `json:"next"`
	Previous string           `json:"previous"`
	Secrets  []BarbicanSecret `json:"secrets"`
	Total    int              `json:"total"`
}

type BarbicanSecret struct {
	Payload      []byte            `json:"payload"`
	Algorithm    interface{}       `json:"algorithm"`
	BitLength    interface{}       `json:"bit_length"`
	ContentTypes map[string]string `json:"content_types"`
	Created      string            `json:"created"`
	CreatorID    string            `json:"creator_id"`
	Expiration   interface{}       `json:"expiration"`
	Mode         interface{}       `json:"mode"`
	Name         string            `json:"name"`
	SecretRef    string            `json:"secret_ref"`
	SecretType   string            `json:"secret_type"`
	Status       string            `json:"status"`
	Updated      string            `json:"updated"`
}
