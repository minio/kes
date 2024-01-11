// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFindVersion(t *testing.T) {
	for i, test := range findVersionsTests {
		version, err := findVersion(test.Root)
		if err == nil && test.ShouldFail {
			t.Fatalf("Test %d should fail but passed", i)
		}
		if err != nil && !test.ShouldFail {
			t.Fatalf("Test %d: failed to find version: %v", i, err)
		}
		if !test.ShouldFail && version != test.Version {
			t.Fatalf("Test %d: got '%s' - want '%s'", i, version, test.Version)
		}
	}
}

var findVersionsTests = []struct {
	Version    string
	Root       *yaml.Node
	ShouldFail bool
}{
	{ // 0 - Document tree with a "version" node
		Version: "v1",
		Root: &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Content: []*yaml.Node{
					{
						Kind:  yaml.ScalarNode,
						Value: "version",
					},
					{
						Kind:  yaml.ScalarNode,
						Value: "v1",
					},
				}},
			},
		},
	},

	{ // 1
		Root:       nil,
		ShouldFail: true,
	},
	{ // 2
		Root:       &yaml.Node{Kind: yaml.ScalarNode},
		ShouldFail: true,
	},
	{ // 3
		Root:       &yaml.Node{Kind: yaml.DocumentNode},
		ShouldFail: true,
	},
	{ // 4
		Root:       &yaml.Node{Kind: yaml.DocumentNode, Content: make([]*yaml.Node, 2)},
		ShouldFail: true,
	},
	{ // 5
		Root: &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Content: []*yaml.Node{
					{
						Kind:  yaml.DocumentNode,
						Value: "version",
					},
				}},
			},
		},
		ShouldFail: true,
	},
	{ // 6
		Root: &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Content: []*yaml.Node{
					{
						Kind:  yaml.ScalarNode,
						Value: "version",
					},
				}},
			},
		},
		ShouldFail: true,
	},
}
