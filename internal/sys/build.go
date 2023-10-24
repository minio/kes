// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package sys

import (
	"errors"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// BinaryInfo contains build information about a Go binary.
type BinaryInfo struct {
	Version  string // The version of this binary
	CommitID string // The git commit hash
	Runtime  string // The Go runtime version, e.g. go1.21.0
	Compiler string // The Go compiler used to build this binary
}

// ReadBinaryInfo returns the ReadBinaryInfo about this program.
func ReadBinaryInfo() (BinaryInfo, error) { return readBinaryInfo() }

var readBinaryInfo = sync.OnceValues[BinaryInfo, error](func() (BinaryInfo, error) {
	const (
		DefaultVersion  = "<unknown>"
		DefaultCommitID = "<unknown>"
		DefaultCompiler = "<unknown>"
	)
	binaryInfo := BinaryInfo{
		Version:  DefaultVersion,
		CommitID: DefaultCommitID,
		Runtime:  runtime.Version(),
		Compiler: DefaultCompiler,
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return binaryInfo, errors.New("sys: binary does not contain build info")
	}

	const (
		GitTimeKey     = "vcs.time"
		GitRevisionKey = "vcs.revision"
		CompilerKey    = "-compiler"
	)
	for _, setting := range info.Settings {
		switch setting.Key {
		case GitTimeKey:
			binaryInfo.Version = strings.ReplaceAll(setting.Value, ":", "-")
		case GitRevisionKey:
			binaryInfo.CommitID = setting.Value
		case CompilerKey:
			binaryInfo.Compiler = setting.Value
		}
	}
	return binaryInfo, nil
})
