// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPL
// license that can be found in the LICENSE file.

package key

import "net/http"

const (
	ErrKeyNotFound errorType = "key does not exist"
	ErrKeyExists   errorType = "key does already exist"
	ErrStoreSealed errorType = "key store is sealed"
)

type errorType string

func (e errorType) Error() string { return string(e) }
func (e errorType) Status() int   { return errCode[e] }

var errCode = map[errorType]int{
	ErrKeyNotFound: http.StatusNotFound,
	ErrKeyExists:   http.StatusBadRequest,
	ErrStoreSealed: http.StatusForbidden,
}

type Store interface {
	Create(string, Secret) error

	Delete(string) error

	Get(string) (Secret, error)
}
