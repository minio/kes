// Copyright 2024 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package cli

import (
	"os"

	tui "github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

var isTerm = term.IsTerminal(int(os.Stdout.Fd())) || term.IsTerminal(int(os.Stderr.Fd()))

// IsTerminal reports whether stdout is a terminal.
func IsTerminal() bool { return isTerm }

// Fg returns a new style with the given foreground
// color. All strings s are rendered with the style.
// For example:
//
//	fmt.Println(cli.Fg(tui.ANSIColor(2), "Hello World"))
func Fg(c tui.TerminalColor, s ...string) tui.Style {
	return tui.NewStyle().Foreground(c).SetString(s...)
}
