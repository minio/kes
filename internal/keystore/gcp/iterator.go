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
	err    error
	closed bool
}

func (i *iterator) Next() (string, bool) {
	if i.closed {
		return "", false
	}

	v, err := i.src.Next()
	if err != nil {
		i.err = err
		if err == gcpiterator.Done {
			i.err = i.Close()
		}
		return "", false
	}
	return path.Base(v.GetName()), true
}

func (i *iterator) Close() error {
	if !i.closed {
		i.closed = true
	}
	return i.err
}
