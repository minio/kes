// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"fmt"
	"os"

	tui "github.com/charmbracelet/lipgloss"
)

// Exit prints args as error message and aborts with exit code 1.
func Exit(args ...any) {
	const FG tui.Color = "#ac0000"
	s := tui.NewStyle().Foreground(FG).Render("Error: ")

	fmt.Fprintln(os.Stderr, s+fmt.Sprint(args...))
	os.Exit(1)
}

// Exitf formats args as error message and aborts with exit code 1.
func Exitf(format string, args ...any) {
	const FG tui.Color = "#ac0000"
	s := tui.NewStyle().Foreground(FG).Render("Error: ")

	fmt.Fprintln(os.Stderr, s+fmt.Sprintf(format, args...))
	os.Exit(1)
}
