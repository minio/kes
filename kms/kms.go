package kms

import (
	"context"
	"errors"
	"net"
	"net/url"
	"time"
)

// Conn is a connection to a KMS.
//
// Multiple goroutines may invoke methods
// on a Conn simultaneously.
type Conn interface {
	// Status returns the current state of the
	// Conn or an error explaining why fetching
	// the State failed.
	//
	// Status returns Unreachable when it fails
	// to reach the KMS.
	// It returns Unavailable when it successfully
	// reaches the KMS but the KMS seems to cannot
	// process some or any requests. One example,
	// would be a KMS that listens and accepts
	// network requests but hasn't been initialized.
	Status(context.Context) (State, error)

	// Create creates a new name-value entry at
	// the KMS if and only if no entry for the
	// given name exists.
	//
	// If such an entry already exists, Create
	// returns kes.ErrKeyExists.
	Create(ctx context.Context, name string, value []byte) error

	// Get returns the value for the given name or
	// an error explaining why fetching the value
	// from the KMS failed.
	//
	// If no entry for the given name exists, Get
	// returns kes.ErrKeyNotFound.
	Get(ctx context.Context, name string) ([]byte, error)

	// Delete deletes the specified entry at the KMS.
	//
	// If no entry for the given name exists, Delete
	// returns kes.ErrKeyNotFound.
	Delete(ctx context.Context, name string) error

	// List returns an iterator over the entries
	// at the KMS.
	//
	// The returned Iter stops fetching entries
	// from the KMS once ctx.Done() returns.
	List(context.Context) (Iter, error)
}

// Iter is an iterator over entries at a KMS.
type Iter interface {
	// Next fetches the next entry from the KMS.
	// It returns false when there are no more entries
	// or once it encounters an error.
	//
	// Once Next returns false, it returns false on any
	// subsequent Next call.
	Next() bool

	// Name returns the name of the latest fetched entry.
	// It returns the same name until Next is called again.
	//
	// As long as Next hasn't been called once or once Next
	// returns false, Name returns the empty string.
	Name() string

	// Close closes the Iter. Once closed, any subsequent
	// Next call returns false.
	//
	// Close returns the first error encountered while iterating
	// over the entires, if any. Otherwise, it returns the error
	// encountered while cleaning up any resources, if any.
	// Subsequent calls to Close return the same error.
	Close() error
}

// FuseIter wraps iter and returns an Iter that
// guarantees:
//   - Next always returns false once it gets closed or
//     encounters an error.
//   - Name always returns the empty string once it gets
//     closed or encounters an error.
//   - Close closes the underlying Iter and always returns
//     the same error on any subsequent call.
func FuseIter(iter Iter) Iter { return &fuseIter{iter: iter} }

type fuseIter struct {
	iter Iter

	closed bool
	err    error
}

func (f *fuseIter) Next() bool {
	if f.closed || f.err != nil {
		return false
	}
	return f.iter.Next()
}

func (f *fuseIter) Name() string {
	if f.closed || f.err != nil {
		return ""
	}
	return f.iter.Name()
}

func (f *fuseIter) Close() error {
	f.closed = true
	if err := f.iter.Close(); f.err == nil {
		f.err = err
	}
	return f.err
}

// State is a structure describing the state of
// a KMS Conn.
type State struct {
	// Latency is the connection latency.
	Latency time.Duration
}

// Unreachable is an error that indicates that the
// KMS is not reachable - for example due to a
// a network error.
type Unreachable struct {
	Err error
}

// IsUnreachable reports whether err is an Unreachable
// error. If IsUnreachable returns true it returns err
// as Unreachable error.
func IsUnreachable(err error) (*Unreachable, bool) {
	var u *Unreachable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}

func (e *Unreachable) Error() string {
	if e.Err == nil {
		return "kms is unreachable"
	}
	return "kms is unreachable: " + e.Err.Error()
}

// Unwrap returns the Unreachable's underlying error,
// if any.
func (e *Unreachable) Unwrap() error { return e.Err }

// Timeout reports whether the Unreachable error
// is caused by a network timeout.
func (e *Unreachable) Timeout() bool {
	if err, ok := e.Err.(net.Error); ok {
		return err.Timeout()
	}
	return false
}

// Unavailable is an error that indicates that the
// KMS is reachable over the network but not ready
// to process requests - e.g. the KMS might not be
// initialized.
type Unavailable struct {
	Err error
}

// IsUnavailable reports whether err is an Unavailable
// error. If IsUnavailable returns true it returns err
// as Unavailable error.
func IsUnavailable(err error) (*Unavailable, bool) {
	var u *Unavailable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}

func (e *Unavailable) Error() string {
	if e.Err == nil {
		return "kms is not available"
	}
	return "kms is not available: " + e.Err.Error()
}

// Unwrap returns the Unavailable's underlying error,
// if any.
func (e *Unavailable) Unwrap() error { return e.Err }

// Dial dials the given addr and returns a new State
// describing the established connection.
//
// If Dial fails to establish a connection due to a network
// error, it returns an error of type Unreachable.
func Dial(ctx context.Context, addr string) (State, error) {
	const (
		HTTPS       = "https://"
		DefaultPort = "443"
	)

	URL, err := url.Parse(addr)
	if err != nil {
		return State{}, err
	}
	if URL.Hostname() == "" {
		// If the URL does not contain a hostname
		// the raw endpoint does not contain a
		// scheme. For example: localhost:443
		// instead of https://localhost:443.
		//
		// In this case, we prepend the
		// https:// scheme to obtain the
		// hostname and port later on.
		URL, err = url.Parse(HTTPS + addr)
		if err != nil {
			return State{}, err
		}
	}

	var (
		host = URL.Hostname()
		port = URL.Port()
	)
	if port == "" {
		port = DefaultPort
	}

	var (
		d     net.Dialer
		start = time.Now()
	)
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	latency := time.Since(start)
	if err != nil {
		return State{}, &Unreachable{Err: err}
	}
	defer c.Close()

	return State{
		Latency: latency,
	}, nil
}
