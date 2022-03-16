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

// Fatal formats writes an error prefix and the operands
// to OS stderr. Then, Fatal terminates the program by
// calling os.Exit(1).
func Fatal(v ...interface{}) {
	fmt.Fprint(os.Stderr, errPrefix)
	fmt.Fprint(os.Stderr, v...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

// Fatalf formats writes an error prefix and the operands,
// formated according to the format specifier, to OS stderr.
// Then, Fatalf terminates the program by calling os.Exit(1).
func Fatalf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, errPrefix+format+"\n", v...)
	os.Exit(1)
}
