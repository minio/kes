// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package keystore

import (
	"errors"
	"slices"
	"strings"
)

// List sorts the names lexicographically and returns the
// first n, if n > 0, names that match the given prefix.
// If n <= 0, List limits the returned slice to a reasonable
// default. If len(names) is greater than n then List returns
// the next name from which to continue.
func List(names []string, prefix string, n int) ([]string, string, error) {
	const N = 1024

	slices.Sort(names)
	if prefix != "" {
		i := slices.IndexFunc(names, func(name string) bool {
			return strings.HasPrefix(name, prefix)
		})
		if i < 0 {
			return []string{}, "", nil
		}
		names = names[i:]

		for i, name := range names {
			if !strings.HasPrefix(name, prefix) {
				return names[:i], "", nil
			}
			if (n > 0 && i > n) || i == N {
				if i == len(names)-1 {
					return names, "", nil
				}
				return names[:i], names[i], nil
			}
		}
	}

	switch {
	case (n <= 0 && len(names) <= N) || len(names) <= n:
		return names, "", nil
	case n <= 0:
		return names[:N], names[N], nil
	default:
		return names[:n], names[n], nil
	}
}

// ErrUnreachable is an error that indicates that the
// Store is not reachable - for example due to a
// a network error.
type ErrUnreachable struct {
	Err error
}

func (e *ErrUnreachable) Error() string {
	if e.Err == nil {
		return "kes: keystore unreachable"
	}
	return "kes: keystore unreachable: " + e.Err.Error()
}

// IsUnreachable reports whether err is an Unreachable
// error. If IsUnreachable returns true it returns err
// as Unreachable error.
func IsUnreachable(err error) (*ErrUnreachable, bool) {
	var u *ErrUnreachable
	if errors.As(err, &u) {
		return u, true
	}
	return nil, false
}
