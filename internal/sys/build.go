// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"runtime/debug"
	"strings"
	"sync"

	"github.com/blang/semver/v4"
)

// BuildInfo contains build information
// about a Go binary.
type BuildInfo struct {
	Version  string
	CommitID string
}

// BinaryInfo returns the BuildInfo of the
// binary itself.
//
// It returns some default information
// when no build information has been
// compiled into the binary.
func BinaryInfo() BuildInfo {
	readBinaryOnce.Do(func() { binaryInfo = readBinaryInfo() })
	return binaryInfo
}

func readBinaryInfo() BuildInfo {
	const (
		DefaultVersion  = "v0.0.0-dev"
		DefaultCommitID = "<unknown>"
	)
	binaryInfo := BuildInfo{
		Version:  DefaultVersion,
		CommitID: DefaultCommitID,
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return binaryInfo
	}

	const (
		TagKey         = "-tags"
		GitRevisionKey = "vcs.revision"

		VersionTag = "version="
	)
	for _, setting := range info.Settings {
		if strings.HasPrefix(setting.Key, TagKey) {
			keys := strings.Split(setting.Value, ",")
			for _, key := range keys {
				if strings.HasPrefix(key, VersionTag) {
					v := strings.TrimPrefix(key, VersionTag)
					if _, err := semver.ParseTolerant(v); err == nil {
						binaryInfo.Version = v
					}
					break
				}
			}
		}
		if setting.Key == GitRevisionKey {
			binaryInfo.CommitID = setting.Value
		}
	}
	return binaryInfo
}

var (
	readBinaryOnce sync.Once
	binaryInfo     BuildInfo // protected by the sync.Once above
)
