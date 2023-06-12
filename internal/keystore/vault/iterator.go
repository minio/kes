// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package vault

import (
	"fmt"
	"strings"

	"github.com/minio/kes/kv"
)

type iterator struct {
	values []interface{}
}

var _ kv.Iter[string] = (*iterator)(nil)

func (i *iterator) Next() (string, bool) {
	for len(i.values) > 0 {
		v := fmt.Sprint(i.values[0])
		i.values = i.values[1:]

		if !strings.HasSuffix(v, "/") { // Ignore prefixes; only iterator over actual entries
			return v, true
		}
	}
	return "", false
}

func (*iterator) Close() error { return nil }
