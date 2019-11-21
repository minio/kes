package kms

import "net/http"

type KeyStore interface {
	Create(Key) error

	Delete(string) error

	Get(string) (Key, error)
}

const (
	ErrKeyNotFound errorType = "key does not exist"
	ErrKeyExists   errorType = "key does already exist"
	ErrSealed      errorType = "key store is sealed"
)

type errorType string

func (e errorType) Error() string { return string(e) }
func (e errorType) Status() int   { return errCode[e] }

var errCode = map[errorType]int{
	ErrKeyNotFound: http.StatusNotFound,
	ErrKeyExists:   http.StatusBadRequest,
	ErrSealed:      http.StatusForbidden,
}
