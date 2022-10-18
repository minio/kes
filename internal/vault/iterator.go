// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"fmt"
	"strings"

	"github.com/minio/kes/kms"
)

type iterator struct {
	values []interface{}
	last   string
}

var _ kms.Iter = (*iterator)(nil)

func (i *iterator) Next() bool {
	for len(i.values) > 0 {
		v := fmt.Sprint(i.values[0])
		i.values = i.values[1:]

		if !strings.HasSuffix(v, "/") { // Ignore prefixes; only iterator over actual entries
			i.last = v
			return true
		}
	}
	return false
}

func (i *iterator) Name() string { return i.last }

func (*iterator) Close() error { return nil }
