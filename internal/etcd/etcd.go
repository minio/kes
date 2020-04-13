// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

// Package etcd implements a key store that stores
// secret keys as key-value entries on an etcd cluster.
package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/minio/kes"
	"github.com/minio/kes/internal/secret"
	"go.etcd.io/etcd/clientv3"
	"go.uber.org/zap"
)

// Login represents etcd user credentials.
// In particular, a username and password.
//
// Additionally to username/password authentication
// etcd supports mTLS authentication via a client
// certificate. In case of mTLS authentication, etcd
// uses the certificate's common name as user name.
//
// However, if both, a client certificate and
// username/password, are provided then the username
// takes precedence over the certificate's common name.
// See:
//   https://github.com/etcd-io/etcd/blob/master/Documentation/op-guide/authentication.md#using-tls-common-name
//
type Login struct {
	// Username is the name of the etcd user.
	Username string

	// Password is the password of the etcd user.
	Password string
}

// Store is a key-value store that saves key-value
// pairs as entries on etcd.
type Store struct {
	// Addr are the HTTP endpoints of a etcd cluster.
	Addr []string

	// Login are the credentials used to authenticate
	// to etcd via username and password.
	Login Login

	// ClientKeyPath is the path to the mTLS client
	// private key to authenticate to etcd via TLS.
	ClientKeyPath string

	// ClientCertPath is the path to the mTLS client
	// certificate to authenticate to etcd via TLS.
	//
	// The etcd cluster will try to infer the user
	// from the certificate's common name.
	//
	// If both, a username and a client certificate,
	// are provided then the username takes precedence
	// over the certificate's common name.
	ClientCertPath string

	// CAPath is the path to the root CA certificate(s)
	// used to verify the TLS certificate presented by
	// the etcd server/cluster. If empty, the host's
	// root CA set is used.
	CAPath string

	// ErrorLog specifies an optional logger for errors
	// when K/V pairs cannot be stored, fetched, deleted
	// or contain invalid content.
	// If nil, logging is done via the log package's
	// standard logger.
	ErrorLog *log.Logger

	client *clientv3.Client
}

var _ secret.Remote = (*Store)(nil)

// Authenticate tries to establish a connection to
// an etcd cluster using the login credentials and/or
// the client TLS certificate.
//
// It returns an error if no connection could be
// established - for instance because of invalid
// authentication credentials.
func (s *Store) Authenticate(ctx context.Context) error {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if s.ClientKeyPath != "" || s.ClientCertPath != "" {
		clientCert, err := tls.LoadX509KeyPair(s.ClientCertPath, s.ClientKeyPath)
		if err != nil {
			return fmt.Errorf("etcd: failed to load TLS certificate: %v", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}
	if s.CAPath != "" {
		caCerts, err := loadCACertificates(s.CAPath)
		if err != nil {
			return err
		}
		tlsConfig.RootCAs = caCerts
	}

	client, err := clientv3.New(clientv3.Config{
		Endpoints:          s.Addr,
		DialTimeout:        5 * time.Second, // Eventually, allow a custom timeout via config.
		MaxCallRecvMsgSize: secret.MaxSize,

		Username: s.Login.Username,
		Password: s.Login.Password,
		TLS:      tlsConfig,

		// Etcd does not allow us to specify a standard
		// library logger nor configure the log sink as
		// io.Writer (only paths / URLs). Therefore, we
		// disable the etcd-internal logging by using
		// the special "/dev/null" path of the zap package.
		// It instructs zap to not write logs.
		//
		// This entire situation is unfortunate but there
		// is not much we can do here.
		LogConfig: &zap.Config{
			Level:             zap.NewAtomicLevelAt(zap.ErrorLevel),
			DisableCaller:     true,
			DisableStacktrace: true,
			Encoding:          "json",
			OutputPaths:       []string{"/dev/null"},
			ErrorOutputPaths:  []string{"/dev/null"},
		},
	})
	if err != nil {
		if err == context.DeadlineExceeded {
			return errors.New("etcd: failed to establish connection: network timeout")
		}
		return err
	}
	s.client = client
	return nil
}

// Create creates the given key-value pair at etcd if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *Store) Create(key, value string) error {
	if s.client == nil {
		s.log(errNoConnection)
		return errNoConnection
	}

	txn := s.client.Txn(context.Background())
	resp, err := txn.If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).Then(clientv3.OpPut(key, value)).Commit()
	if err != nil {
		s.logf("etcd: failed to create '%s': %v", key, err)
		return err
	}
	if !resp.Succeeded {
		return kes.ErrKeyExists
	}
	return nil
}

// Delete deletes a the value associated with the given key
// from etcd, if it exists.
func (s *Store) Delete(key string) error {
	if s.client == nil {
		s.log(errNoConnection)
		return errNoConnection
	}

	_, err := s.client.Delete(context.Background(), key)
	if err != nil {
		s.logf("etcd: failed to delete '%s': %v", key, err)
		return err
	}
	return nil
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(key string) (string, error) {
	if s.client == nil {
		s.log(errNoConnection)
		return "", errNoConnection
	}

	resp, err := s.client.Get(context.Background(), key)
	if err != nil {
		return "", err
	}
	if len(resp.Kvs) == 0 {
		return "", kes.ErrKeyNotFound
	}
	if len(resp.Kvs) > 1 {
		s.logf("etcd: '%s' contains more than one secrets", key)
		return "", errors.New("secret is malformed")
	}

	// It may be tempting to use resp.Kvs[0].CreateRevision
	// and/or resp.Kvs[0].ModRevision to try to detect
	// external modification. However, this does not work as
	// expected. For example the create/mod revision won't
	// differ when the value actually changes:
	//  1. etcdctl put my-key my-value
	//  2. etcdctl put my-key other-value
	//  => Now, create-revision == mod-revision
	//
	// However, in case of:
	//  1. etcdctl put my-key my-value
	//  2. etcdctl put my-key my-value
	//  => Now, create-revision != mod-revision
	//
	// The revision is a value that corresponds to
	// all changes that happened so far. So, for a given
	// key-value pair the create and modify revision
	// only differ when either the value or the key
	// change - but not both.

	return string(resp.Kvs[0].Value), nil
}

// errNoConnection is the error returned and logged by
// the key store if the etcd client hasn't been initialized.
//
// This error is returned by Create, Get, Delete, a.s.o.
// in case of an invalid configuration - i.e. when Authenticate()
// hasn't been called.
var errNoConnection = errors.New("etcd: no connection to cluster")

func (s *Store) log(v ...interface{}) {
	if s.ErrorLog == nil {
		log.Println(v...)
	} else {
		s.ErrorLog.Println(v...)
	}
}

func (s *Store) logf(format string, v ...interface{}) {
	if s.ErrorLog == nil {
		log.Printf(format, v...)
	} else {
		s.ErrorLog.Printf(format, v...)
	}
}

// loadCACertificates returns a new x509.CertPool
// with all certificates found at the given path.
//
// If the path points to a file then loadCACertificates
// tries to parse it as X.509 certificate and returns
// a cert pool containing this certificate.
//
// If the path points to a directory then
// loadCACertificates tries to parse any file inside
// path as X.509 certificate and adds it to the
// cert pool on success. It does not search for files
// recursively.
func loadCACertificates(path string) (*x509.CertPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}

	certs := x509.NewCertPool()
	if !stat.IsDir() {
		bytes, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, err
		}
		if !certs.AppendCertsFromPEM(bytes) {
			return nil, fmt.Errorf("etcd: '%s' does not contain a PEM-encoded certificate", path)
		}
		return certs, nil
	}

	// If the path is a directory, list all
	// files and try to parse each one.
	files, err := f.Readdir(0)
	if err != nil {
		return nil, err
	}

	var certFound bool
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		bytes, err := ioutil.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("etcd: failed to read file '%s': %v", filepath.Join(path, file.Name()), err)
		}
		if certs.AppendCertsFromPEM(bytes) {
			certFound = true
		}
	}
	if !certFound {
		return nil, fmt.Errorf("etcd: '%s' seems to contain no PEM-encoded certificate", path)
	}
	return certs, nil
}
