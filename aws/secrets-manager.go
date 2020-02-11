// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/minio/kes"
	xerrors "github.com/minio/kes/errors"
	"github.com/minio/kes/internal/cache"
)

// Credentials represents static AWS credentials:
// access key, secret key and a session token
type Credentials struct {
	AccessKey    string // The AWS access key
	SecretKey    string // The AWS secret key
	SessionToken string // The AWS session token
}

// SecretsManager is a secret key store that
// saves/fetches secret keys on/from the AWS
// Secrets Manager.
// See: https://aws.amazon.com/secrets-manager
type SecretsManager struct {
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

	// CacheExpireAfter is the duration after which
	// cache entries expire such that they have to
	// be loaded from the backend storage again.
	CacheExpireAfter time.Duration

	// CacheExpireUnusedAfter is the duration after
	// which not recently used cache entries expire
	// such that they have to be loaded from the
	// backend storage again.
	// Not recently is defined as: CacheExpireUnusedAfter / 2
	CacheExpireUnusedAfter time.Duration

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	cache  cache.Cache
	client *secretsmanager.SecretsManager
	once   uint32
}

// Create adds the given secret key to the store if and only
// if no entry for name exists. If an entry already exists
// it returns kes.ErrKeyExists.
//
// In particular, Create creates a new entry on AWS Secrets
// Manager with the given name containing the secret.
func (store *SecretsManager) Create(name string, secret kes.Secret) error {
	if store.client == nil {
		store.log(errNoConnection)
		return errNoConnection
	}
	store.initialize()
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
		err = fmt.Errorf("aws: failed to create secret '%s': %v", name, err)
		store.log(err)
		return err
	}
	store.cache.Set(name, secret)
	return nil
}

// Get returns the secret key associated with the given name.
// If no entry for name exists, Get returns kes.ErrKeyNotFound.
//
// In particular, Get reads the secret key from the corresponding
// entry at AWS Secrets Manager.
func (store *SecretsManager) Get(name string) (kes.Secret, error) {
	if store.client == nil {
		store.log(errNoConnection)
		return kes.Secret{}, errNoConnection
	}
	store.initialize()
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
				return kes.Secret{}, xerrors.New(http.StatusForbidden, fmt.Sprintf("aws: cannot access secret '%s': %v", name, err))
			case secretsmanager.ErrCodeResourceNotFoundException:
				return kes.Secret{}, kes.ErrKeyNotFound
			}
		}
		err = fmt.Errorf("aws: failed to read secret '%s': %v", name, err)
		store.log(err)
		return kes.Secret{}, err
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
			store.logf("aws: failed to read secret '%s': %v", name, err)
			return secret, err
		}
	} else {
		if _, err = secret.ReadFrom(bytes.NewReader(response.SecretBinary)); err != nil {
			store.logf("aws: failed to read secret '%s': %v", name, err)
			return secret, err
		}
	}
	secret, _ = store.cache.Add(name, secret)
	return secret, nil
}

// Delete removes a the secret key with the given name
// from the key store and deletes the corresponding AWS
// Secrets Manager entry, if it exists.
func (store *SecretsManager) Delete(name string) error {
	if store.client == nil {
		store.log(errNoConnection)
		return errNoConnection
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
		err = fmt.Errorf("aws: failed to delete secret '%s': %v", name, err)
		store.log(err)
		return err
	}
	return nil
}

// Authenticate tries to establish a connection to
// the AWS Secrets Manager using the login credentials.
func (store *SecretsManager) Authenticate() error {
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

// errNoConnection is the error returned and logged by
// the key store if the AWS Secrets Manager client hasn't
// been initialized.
//
// This error is returned by Create, Get, Delete, a.s.o.
// in case of an invalid configuration - i.e. when Authenticate()
// hasn't been called.
var errNoConnection = errors.New("aws: no connection to AWS secrets manager")

func (store *SecretsManager) initialize() {
	if atomic.CompareAndSwapUint32(&store.once, 0, 1) {
		store.cache.StartGC(context.Background(), store.CacheExpireAfter)
		store.cache.StartUnusedGC(context.Background(), store.CacheExpireUnusedAfter/2)
	}
}

func (store *SecretsManager) log(v ...interface{}) {
	if store.ErrorLog == nil {
		log.Println(v...)
	} else {
		store.ErrorLog.Println(v...)
	}
}

func (store *SecretsManager) logf(format string, v ...interface{}) {
	if store.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		store.ErrorLog.Printf(format, v...)
	}
}
