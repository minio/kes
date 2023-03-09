// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package https

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
)

// CertPoolFromFile returns a X.509 certificate pool that contains
// all system root certificates from x509.SystemCertPool and
// the certificates loaded from the given filename.
//
// If filename is a directory LoadCertPool parses all files inside
// as PEM-encoded X.509 certificate and adds them to the certificate
// pool.
// Otherwise, LoadCertPool parses filename as PEM-encoded X.509
// certificate file and adds it to the certificate pool.
//
// It returns the first error it encounters, if any, when parsing
// a X.509 certificate file.
func CertPoolFromFile(filename string) (*x509.CertPool, error) {
	stat, err := os.Stat(filename)
	if err != nil {
		return nil, err
	}

	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if !stat.IsDir() {
		if err = appendCertificate(pool, filename); err != nil {
			return nil, err
		}
		return pool, nil
	}

	files, err := os.ReadDir(filename)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if err = appendCertificate(pool, filepath.Join(filename, file.Name())); err != nil {
			return nil, err
		}
	}
	return pool, nil
}

// appendCertificate parses the given file as X.509
// certificate and adds it to the given pool.
//
// It returns an error if the certificate couldn't
// be added.
func appendCertificate(pool *x509.CertPool, filename string) error {
	b, err := readCertificate(filename)
	if err != nil {
		return err
	}
	if !pool.AppendCertsFromPEM(b) {
		return errors.New("https: failed to add '" + filename + "' as CA certificate")
	}
	return nil
}
