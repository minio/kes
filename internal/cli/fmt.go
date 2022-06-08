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

// Fatal writes an error prefix and the operands
// to OS stderr. Then, Fatal terminates the program by
// calling os.Exit(1).
func Fatal(v ...any) {
	fmt.Fprint(os.Stderr, errPrefix)
	fmt.Fprint(os.Stderr, v...)
	fmt.Fprintln(os.Stderr)
	os.Exit(1)
}

// Fatalf writes an error prefix and the operands,
// formated according to the format specifier, to OS stderr.
// Then, Fatalf terminates the program by calling os.Exit(1).
func Fatalf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, errPrefix+format+"\n", v...)
	os.Exit(1)
}

// Print formats using the default formats for its operands and
// writes to standard output. Spaces are added between operands
// when neither is a string.
// It returns the number of bytes written and any write error
// encountered.
func Print(v ...any) (int, error) { return fmt.Print(v...) }

// Printf formats according to a format specifier and writes to
// standard output. It returns the number of bytes written and
// any write error encountered.
func Printf(format string, v ...any) (int, error) { return fmt.Printf(format, v...) }

// Println formats using the default formats for its operands and writes to
// standard output. Spaces are always added between operands and a newline
// is appended.
// It returns the number of bytes written and any write error encountered.
func Println(v ...any) (int, error) { return fmt.Println(v...) }
