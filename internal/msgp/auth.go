// Copyright 2023 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package msgp

import "time"

//go:generate msgp -io=false

// Identity is the message pack representation of an auth.Identity.
type Identity struct {
	Policy    string        `msg:"0"`
	IsAdmin   bool          `msg:"1"`
	Children  []string      `msg:"2"`
	TTL       time.Duration `msg:"3"`
	ExpiresAt time.Time     `msg:"4"`
	CreatedAt time.Time     `msg:"5"`
	CreatedBy string        `msg:"6"`
}

// Policy is the message pack representation of an auth.Policy.
type Policy struct {
	Allow     map[string]struct{} `msg:"0"`
	Deny      map[string]struct{} `msg:"1"`
	CreatedAt time.Time           `msg:"2"`
	CreatedBy string              `msg:"3"`
}
