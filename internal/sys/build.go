// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"runtime/debug"
	"strings"
	"sync"
)

// BuildInfo contains build information
// about a Go binary.
type BuildInfo struct {
	Version  string
	CommitID string
	Data     string
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
		DefaultVersion  = "<unknown>"
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
		GitTimeKey     = "vcs.time"
		GitRevisionKey = "vcs.revision"
	)
	for _, setting := range info.Settings {
		if setting.Key == GitTimeKey {
			binaryInfo.Version = strings.ReplaceAll(setting.Value, ":", "-")
		}
		if setting.Key == GitRevisionKey {
			binaryInfo.CommitID = setting.Value
		}
	}
	binaryInfo.Data = info.String()
	return binaryInfo
}

var (
	readBinaryOnce sync.Once
	binaryInfo     BuildInfo // protected by the sync.Once above
)
