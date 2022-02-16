// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var errPrefix = color.RedString("Error: ")

func Fatal(v ...interface{}) {
	fmt.Fprint(os.Stderr, errPrefix)
	fmt.Fprint(os.Stderr, v...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

func Fatalf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, errPrefix+format+"\n", v...)
	os.Exit(1)
}
