// Copyright 2022 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"os"
	"strings"

	tui "github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	flag "github.com/spf13/pflag"
)

// colorOption is a CLI Flag that controls
// terminal output colorization. It can be
// set to one of the following values:
//   · always
//   · auto  (default)
//   · never
type colorOption struct {
	value string
}

var _ flag.Value = (*colorOption)(nil)

func (c *colorOption) Colorize() bool {
	v := strings.ToLower(c.value)
	return v == "always" || ((v == "auto" || v == "") && isTerm(os.Stdout))
}

func (c *colorOption) String() string { return c.value }

func (c *colorOption) Set(value string) error {
	switch strings.ToLower(value) {
	case "always":
		if p := tui.ColorProfile(); p == termenv.Ascii {
			tui.SetColorProfile(termenv.ANSI256)
		}
		c.value = value
		return nil
	case "auto", "":
		c.value = value
		return nil
	case "never":
		tui.SetColorProfile(termenv.Ascii)
		c.value = value
		return nil
	default:
		return errors.New("invalid color option")
	}
}

func (c *colorOption) Type() string { return "color option" }
