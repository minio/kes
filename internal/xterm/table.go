// Copyright 2020 - MinIO, Inc. All rights reserved.
// Use of this source code is governed by the AGPLv3
// license that can be found in the LICENSE file.

package xterm

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh/terminal"
)

// HCell represents a single header cell of a table.
// A table with n columns has n header cells. A HCell
// defines certain properties for all cells of the same
// column - like the column width.
type HCell struct {
	Cell
	Width     float64   // The width of the column in percent.
	Alignment Alignment // The text alignment of the column.
}

// NewCell returns a new tabel cell with the given
// text and no color.
func NewCell(text string) *Cell {
	return &Cell{
		Text: text,
	}
}

// Cell represents a single table cell.
type Cell struct {
	Text  string
	Color *color.Color
}

// Table represents a table UI that consists of
// n columns and a sliding window of rows.
//
// Each column has a header cell that defines the
// column width and other properties.
//
// New rows can be added to the table but it remembers
// only a sliding window of rows. Once the capacity
// of the table is reached the window is moved forward
// whenever a new row is added such that olds rows get
// dropped.
//
// In any case, the table only prints the latest m rows
// that fit on the STDOUT terminal window. So, a table
// keeps a sliding window of the latest n rows and prints
// a view of the latest m rows, that fits on the screen,
// to STDOUT.
type Table struct {
	lock     sync.Mutex
	header   []*HCell
	rows     [][]*Cell
	rowLimit int
}

// NewTable creates a new table with len(headers)
// columns. Each column has its on header title and
// in bold text and aligned to the left.
// All columns have the same width of 1/len(headers).
func NewTable(headers ...string) *Table {
	bold := color.New(color.Bold)
	hCells := make([]*HCell, len(headers))
	for i, header := range headers {
		hCells[i] = &HCell{
			Cell: Cell{
				Text:  header,
				Color: bold,
			},
			Width:     1 / float64(len(headers)),
			Alignment: AlignLeft,
		}
	}
	return &Table{
		header:   hCells,
		rows:     [][]*Cell{},
		rowLimit: 1000,
	}
}

// Header returns the header cell of each column.
func (t *Table) Header() []*HCell { return t.header }

// AddRow adds a new row to the table. If the capacity
// of the table is reached older rows get dropped.
func (t *Table) AddRow(cells ...*Cell) { t.SetRow(-1, cells...) }

// SetRow replaces a row at the given index. If the index
// is negative or exceeds the size of the table the given
// row is appended at the end.
func (t *Table) SetRow(at int, cells ...*Cell) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if at < 0 || len(t.rows) <= at {
		if len(t.rows) <= t.rowLimit {
			t.rows = append(t.rows, cells)
		} else {
			t.rows = t.rows[len(t.rows)-1-t.rowLimit:]
			t.rows = append(t.rows, cells)
		}
	} else {
		t.rows[at] = cells
	}
}

// Draw first cleans the screen and then prints a
// view of the table to STDOUT. The view is adjusted
// to the terminal width and height.
func (t *Table) Draw() {
	t.lock.Lock()
	defer t.lock.Unlock()

	width, height, _ := terminal.GetSize(int(os.Stdout.Fd()))

	fmt.Print("\033[3J\033[0;0H", "\r") // ASCII sequence to clean scroll + move to position (0,0)
	fmt.Printf("\033[%dM", height+1)    // ASCII sequence to delete height+1 rows
	fmt.Print("\033[0;0H", "\r")        // ASCII sequence to move to position (0,0)

	// Limit the number of rows to print such that we
	// print the header + latest n rows depending on
	// the window size.
	var rows = t.rows
	if height > 5 && len(rows) > height-5 {
		rows = rows[len(rows)-(height-5):]
	}

	fmt.Println(t.borderString(width, '┌', '┬', '┐'))
	fmt.Println(t.headerString(width))
	fmt.Println(t.borderString(width, '├', '┼', '┤'))
	for _, row := range rows {
		fmt.Println(t.rowString(width, row...))
	}
	fmt.Println(t.borderString(width, '└', '┴', '┘'))
}

// headerString returns the header of the table
// where each header cell consumes the specified
// fraction of width.
func (t *Table) headerString(width int) string {
	var header strings.Builder

	header.WriteRune('│')
	for _, h := range t.header {
		w := int(float64(width) * h.Width)

		s := h.Alignment.Format(" "+h.Text+" ", w-1)
		if h.Color != nil {
			s = h.Color.Sprint(s)
		}
		header.WriteString(s)
		header.WriteRune('│')
	}
	return header.String()
}

// rowString returns a string representation of row
// where each cell consumes a fraction of width -  like
// specified by the corresponding column.
func (t *Table) rowString(width int, row ...*Cell) string {
	var header strings.Builder

	header.WriteRune('│')
	for i := range t.header {
		w := int(float64(width) * t.header[i].Width)

		s := t.header[i].Alignment.Format(" "+row[i].Text+" ", w-1)
		if row[i].Color != nil {
			s = row[i].Color.Sprint(s)
		}
		header.WriteString(s)
		header.WriteRune('│')
	}
	return header.String()
}

// borderString retruns a string representation of a
// table border that starts with left contains a
// separator whenever a new column starts/ends and
// ends with right.
//
// For instance, it may returns the following border
// string:
//  table.borderString(width, '┌', '┬', '┐'))
//  ┌───────┬────────┬───────┐
func (t *Table) borderString(width int, left, separator, right rune) string {
	var border strings.Builder

	border.WriteRune(left)
	for i, h := range t.header {
		w := int(float64(width) * h.Width)

		border.WriteString(strings.Repeat("─", w-1))
		if i < len(t.header)-1 {
			border.WriteRune(separator)
		}
	}
	border.WriteRune(right)
	return border.String()
}
