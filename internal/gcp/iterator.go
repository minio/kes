// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"net/http"

	"github.com/minio/kes"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	gcpiterator "google.golang.org/api/iterator"
)

var errListKey = kes.NewError(http.StatusBadGateway, "bad gateway: failed to list keys")

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
