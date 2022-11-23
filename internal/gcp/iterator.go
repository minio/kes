// Copyright 2021 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package gcp

import (
	"path"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	gcpiterator "google.golang.org/api/iterator"
)

type iterator struct {
	src    *secretmanager.SecretIterator
	last   string
	err    error
	closed bool
}

func (i *iterator) Next() bool {
	if i.closed {
		return false
	}
	v, err := i.src.Next()
	if err == gcpiterator.Done {
		i.err = i.Close()
		return false
	}
	if err != nil {
		i.err = err
		return false
	}
	i.last = path.Base(v.GetName())
	return true
}

func (i *iterator) Name() string { return i.last }

func (i *iterator) Close() error {
	if !i.closed {
		i.closed = true
		i.last = ""
	}
	return i.err
}
