// Copyright 2019 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package kes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
)

type Policy struct {
	patterns []string
}

func NewPolicy(patterns ...string) (*Policy, error) {
	for _, pattern := range patterns {
		if _, err := path.Match(pattern, pattern); err != nil {
			return nil, err
		}
	}
	return &Policy{
		patterns: patterns,
	}, nil
}

func (p Policy) MarshalJSON() ([]byte, error) {
	type PolicyJSON struct {
		Patterns []string `json:"paths"`
	}

	policy := PolicyJSON{Patterns: p.patterns}
	if len(policy.Patterns) == 0 {
		policy.Patterns = []string{} // marshal nil as empty array ([]) -  not null
	}
	return json.Marshal(policy)
}

func (p *Policy) UnmarshalJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()

	var policyJSON struct {
		Patterns []string `json:"paths"`
	}
	if err := d.Decode(&policyJSON); err != nil {
		return err
	}
	for _, pattern := range policyJSON.Patterns {
		if _, err := path.Match(pattern, pattern); err != nil {
			return err
		}
	}
	p.patterns = policyJSON.Patterns
	return nil
}

func (p *Policy) String() string {
	var builder strings.Builder
	fmt.Fprintln(&builder, "[")
	for _, pattern := range p.patterns {
		if pattern != "" {
			fmt.Fprintf(&builder, "  %s\n", pattern)
		}
	}
	fmt.Fprintln(&builder, "]")
	return builder.String()
}

func (p *Policy) Verify(r *http.Request) error {
	for _, pattern := range p.patterns {
		if ok, err := path.Match(pattern, r.URL.Path); ok && err == nil {
			return nil
		}
	}
	return ErrNotAllowed
}
