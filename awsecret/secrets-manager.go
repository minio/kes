// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package awsecret

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/cache"
)

// Credentials represents static AWS credentials:
// access key, secret key and a session token
type Credentials struct {
	AccessKey    string // The AWS access key
	SecretKey    string // The AWS secret key
	SessionToken string // The AWS session token
}

// KeyStore is a secret key store that saves/fetches
// secret keys on/from the AWS Secrets Manager.
// See: https://aws.amazon.com/secrets-manager
type KeyStore struct {
	// Addr is the HTTP address of the AWS Secret
	// Manager. In general, you want to AWS directly.
	// Therefore, use an address of the following
	// form: secretsmanager.<region>.amazonaws.com
	Addr string
	// Region is the AWS region. Even though the Addr
	// endpoint contains that information already, this
	// field is mandatory.
	Region string
	// The AWS-KMS key ID specifying the AWS-KMS key
	// that is used to encrypt (and decrypt) the
	// secret values stored at AWS Secrets Manager.
	KmsKeyID string

	// Login contains the AWS credentials (access/secret key).
	Login Credentials

	cache  cache.Cache
	client *secretsmanager.SecretsManager
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
//
// In particular, Create creates a new entry on AWS Secrets
// Manager with the given name containing the secret.
func (store *KeyStore) Create(name string, secret kes.Secret) error {
	if store.client == nil {
		panic("awsecret: key store is not connected to AWS secret manager")
	}
	if _, ok := store.cache.Get(name); ok {
		return kes.ErrKeyExists
	}

	createOpt := secretsmanager.CreateSecretInput{
		Name:         aws.String(name),
		SecretString: aws.String(secret.String()),
	}
	if store.KmsKeyID != "" {
		createOpt.KmsKeyId = aws.String(store.KmsKeyID)
	}
	if _, err := store.client.CreateSecret(&createOpt); err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case secretsmanager.ErrCodeResourceExistsException:
				return kes.ErrKeyExists
			}
		}
		return fmt.Errorf("aws: Failed to create secret: %v", err)
	}
	store.cache.Set(name, secret)
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the corresponding
// entry at AWS Secrets Manager.
func (store *KeyStore) Get(name string) (kes.Secret, error) {
	if store.client == nil {
		panic("awsecret: key store is not connected to AWS secret manager")
	}
	if secret, ok := store.cache.Get(name); ok {
		return secret, nil
	}

	response, err := store.client.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(name),
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				return kes.Secret{}, kes.NewError(http.StatusForbidden, fmt.Sprintf(""))
			case secretsmanager.ErrCodeResourceNotFoundException:
				return kes.Secret{}, kes.ErrKeyNotFound
			}
		}
		return kes.Secret{}, fmt.Errorf("aws: Failed to load secret: %v", err)
	}

	// AWS has two different ways to store a secret. Either as
	// "SecretString" or as "SecretBinary". While they *seem* to
	// be equivalent from an API point of view, AWS console e.g.
	// only shows "SecretString" not "SecretBinary".
	// However, AWS demands and specifies that only one is present -
	// either "SecretString" or "SecretBinary" - we can check which
	// one is present and safely assume that the other one isn't.
	var secret kes.Secret
	if response.SecretString != nil {
		if err = secret.ParseString(*response.SecretString); err != nil {
			return secret, err
		}
	} else {
		if _, err = secret.ReadFrom(bytes.NewReader(response.SecretBinary)); err != nil {
			return secret, err
		}
	}
	secret, _ = store.cache.Add(name, secret)
	return secret, nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the corresponding AWS
// Secrets Manager entry, if it exists.
func (store *KeyStore) Delete(name string) error {
	if store.client == nil {
		panic("awsecret: key store is not connected to AWS secret manager")
	}
	store.cache.Delete(name)

	_, err := store.client.DeleteSecret(&secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(name),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			if err.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				return nil
			}
		}
		return fmt.Errorf("aws: Failed to create secret: %v", err)
	}
	return nil
}

// Authenticate tries to establish a connection to
// the AWS Secrets Manager using the login credentials.
func (store *KeyStore) Authenticate() error {
	session, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Endpoint: aws.String(store.Addr),
			Region:   aws.String(store.Region),
			Credentials: credentials.NewStaticCredentials(
				store.Login.AccessKey,
				store.Login.SecretKey,
				store.Login.SessionToken,
			),
		},
		SharedConfigState: session.SharedConfigDisable,
	})
	if err != nil {
		return err
	}
	store.client = secretsmanager.New(session)
	return nil
}
