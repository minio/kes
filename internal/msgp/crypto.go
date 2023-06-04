// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import "time"

//go:generate msgp -io=false

type SecretKey struct {
	Value  []byte `msg:"0"`
	Cipher uint   `msg:"1"`
}

type SecretKeyVersion struct {
	Key       SecretKey `msg:"0"`
	CreatedAt time.Time `msg:"1"`
	CreatedBy string    `msg:"2"`
}

type SecretKeyRing struct {
	Versions map[string]SecretKeyVersion `msg:"0"`
	N        uint32                      `msg:"1"`
	Latest   uint32                      `msg:"2"`
}

type Secret struct {
	Versions map[string]SecretVersion `msg:"0"`
	N        uint32                   `msg:"1"`
	Latest   uint32                   `msg:"2"`
}

type SecretVersion struct {
	Value     []byte    `msg:"0"`
	Type      uint      `msg:"1"`
	CreatedAt time.Time `msg:"2"`
	CreatedBy string    `msg:"3"`
}
