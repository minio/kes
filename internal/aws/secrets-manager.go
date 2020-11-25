// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package aws

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
)

// Credentials represents static AWS credentials:
// access key, secret key and a session token
type Credentials struct {
	AccessKey    string // The AWS access key
	SecretKey    string // The AWS secret key
	SessionToken string // The AWS session token
}

// SecretsManager is a  key-value store that
// saves/fetches values as secrets  on/from the AWS
// Secrets Manager.
// See: https://aws.amazon.com/secrets-manager
type SecretsManager struct {
	// Addr is the HTTP address of the AWS Secret
	// Manager. In general, the address has the
	// following form:
	//  secretsmanager.<region>.amazonaws.com
	Addr string

	// Region is the AWS region. Even though the Addr
	// endpoint contains that information already, this
	// field is mandatory.
	Region string

	// The KMSKeyID is the AWS-KMS key ID specifying the
	// AWS-KMS key that is used to encrypt (and decrypt) the
	// values stored at AWS Secrets Manager.
	KMSKeyID string

	// Login contains the AWS credentials (access/secret key).
	Login Credentials

	// ErrorLog specifies an optional logger for errors
	// when files cannot be opened, deleted or contain
	// invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	client *secretsmanager.SecretsManager
}

var _ secret.Remote = (*SecretsManager)(nil)

var (
	errCreateKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to create key")
	errGetKey    = kes.NewError(http.StatusBadGateway, "bad gateway: failed to access key")
	errDeleteKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to delete key")
	errListKey   = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")
)

// Create stores the given key-value pair at the AWS SecretsManager
// if and only if it doesn't exists. If such an entry already exists
// it returns kes.ErrKeyExists.
//
// If the SecretsManager.KMSKeyID is set AWS will use this key ID to
// encrypt the values. Otherwise, AWS will use the default key ID for
// encrypting secrets at the AWS SecretsManager.
func (s *SecretsManager) Create(key, value string) error {
	if s.client == nil {
		s.logf("aws: no connection to AWS secrets manager: %q", s.Addr)
		return errCreateKey
	}

	createOpt := secretsmanager.CreateSecretInput{
		Name:         aws.String(key),
		SecretString: aws.String(value),
	}
	if s.KMSKeyID != "" {
		createOpt.KmsKeyId = aws.String(s.KMSKeyID)
	}
	if _, err := s.client.CreateSecret(&createOpt); err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case secretsmanager.ErrCodeResourceExistsException:
				return kes.ErrKeyExists
			}
		}
		s.logf("aws: failed to create %q: %v", key, err)
		return errCreateKey
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for key exists, it returns kes.ErrKeyNotFound.
func (s *SecretsManager) Get(key string) (string, error) {
	if s.client == nil {
		s.logf("aws: no connection to AWS secrets manager: %q", s.Addr)
		return "", errGetKey
	}

	response, err := s.client.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(key),
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			switch err.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				return "", kes.NewError(http.StatusForbidden, fmt.Sprintf("aws: cannot access %q: %v", key, err))
			case secretsmanager.ErrCodeResourceNotFoundException:
				return "", kes.ErrKeyNotFound
			}
		}
		s.logf("aws: failed to read %q: %v", key, err)
		return "", errGetKey
	}

	// AWS has two different ways to store a secret. Either as
	// "SecretString" or as "SecretBinary". While they *seem* to
	// be equivalent from an API point of view, AWS console e.g.
	// only shows "SecretString" not "SecretBinary".
	// However, AWS demands and specifies that only one is present -
	// either "SecretString" or "SecretBinary" - we can check which
	// one is present and safely assume that the other one isn't.
	if response.SecretString != nil {
		return *response.SecretString, nil
	}
	return string(response.SecretBinary), nil
}

// Delete removes the key-value pair from the AWS SecretsManager, if
// it exists.
func (s *SecretsManager) Delete(key string) error {
	if s.client == nil {
		s.logf("aws: no connection to AWS secrets manager: %q", s.Addr)
		return errDeleteKey
	}

	_, err := s.client.DeleteSecret(&secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(key),
		ForceDeleteWithoutRecovery: aws.Bool(true),
	})
	if err != nil {
		if err, ok := err.(awserr.Error); ok {
			if err.Code() == secretsmanager.ErrCodeResourceNotFoundException {
				return nil
			}
		}
		s.logf("aws: failed to delete %q: %v", key, err)
		return errDeleteKey
	}
	return nil
}

// List returns a new Iterator over the names of
// all stored keys.
func (s *SecretsManager) List(ctx context.Context) (secret.Iterator, error) {
	if s.client == nil {
		s.logf("aws: no connection to AWS secrets manager: %q", s.Addr)
		return nil, errDeleteKey
	}

	values := make(chan string, 10)
	iterator := &iterator{
		values: values,
	}
	go func() {
		defer close(values)
		err := s.client.ListSecretsPagesWithContext(ctx, &secretsmanager.ListSecretsInput{}, func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
			for _, secret := range page.SecretList {
				values <- *secret.Name
			}

			// The pagination is stopped once we return false.
			// If lastPage is true then we reached the end. Therefore,
			// we return !lastPage which then is false.
			return !lastPage
		})

		if err != nil {
			s.logf("aws: failed to list keys: %v", err)
			iterator.SetErr(errListKey)
		}
	}()
	return iterator, nil
}

type iterator struct {
	values <-chan string
	last   string

	lock sync.Mutex
	err  error
}

func (i *iterator) Next() bool {
	v, ok := <-i.values
	if !ok {
		return false
	}
	i.last = v
	return true
}

func (i *iterator) Value() string { return i.last }

func (i *iterator) Err() error {
	i.lock.Lock()
	defer i.lock.Unlock()
	return i.err
}

func (i *iterator) SetErr(err error) {
	i.lock.Lock()
	i.err = err
	i.lock.Unlock()
}

// Authenticate tries to establish a connection to
// the AWS Secrets Manager using the login credentials.
func (s *SecretsManager) Authenticate() error {
	credentials := credentials.NewStaticCredentials(
		s.Login.AccessKey,
		s.Login.SecretKey,
		s.Login.SessionToken,
	)
	if s.Login.AccessKey == "" && s.Login.SecretKey == "" && s.Login.SessionToken == "" {
		// If all login credentials (access key, secret key and session token) are empty
		// we pass no (not empty) credentials to the AWS SDK. The SDK will try to fetch
		// the credentials from:
		//  - Environment Variables
		//  - Shared Credentials file
		//  - EC2 Instance Metadata
		// In particular, when running a kes server on an EC2 instance, the SDK will
		// automatically fetch the temp. credentials from the EC2 metadata service.
		// See: AWS IAM roles for EC2 instances.
		credentials = nil
	}

	session, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Endpoint:    aws.String(s.Addr),
			Region:      aws.String(s.Region),
			Credentials: credentials,
		},
		SharedConfigState: session.SharedConfigDisable,
	})
	if err != nil {
		return err
	}
	s.client = secretsmanager.New(session)
	return nil
}

func (s *SecretsManager) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}
