// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package secret

type Store interface {
	Create(string, Secret) error

	Delete(string) error

	Get(string) (Secret, error)
}
