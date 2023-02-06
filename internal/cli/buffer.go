package cli

import (
	"fmt"
	"strings"

	tui "github.com/charmbracelet/lipgloss"
)

// A Buffer is used to efficiently build a string
// to display on a terminal.
type Buffer struct {
	s strings.Builder
}

// Sprint appends to the Buffer.
// Arguments are handled in the manner
// of fmt.Print.
func (b *Buffer) Sprint(v ...any) *Buffer {
	b.s.WriteString(fmt.Sprint(v...))
	return b
}

// Sprintf appends to the Buffer.
// Arguments are handled in the manner
// of fmt.Printf.
func (b *Buffer) Sprintf(format string, v ...any) *Buffer {
	b.s.WriteString(fmt.Sprintf(format, v...))
	return b
}

// Sprintln appends to the Buffer.
// Arguments are handled in the manner
// of fmt.Println.
func (b *Buffer) Sprintln(v ...any) *Buffer {
	b.s.WriteString(fmt.Sprintln(v...))
	return b
}

// Stylef appends the styled string to the Buffer.
// Arguments are handled in the manner of fmt.Printf
// before styling.
func (b *Buffer) Stylef(style tui.Style, format string, v ...any) *Buffer {
	b.s.WriteString(style.Render(fmt.Sprintf(format, v...)))
	return b
}

// Styleln appends the styled string to the Buffer.
// Arguments are handled in the manner of fmt.Println
// before styling.
func (b *Buffer) Styleln(style tui.Style, v ...any) *Buffer {
	b.s.WriteString(style.Render(fmt.Sprint(v...)))
	b.s.WriteByte('\n')
	return b
}

// WriteByte appends the byte c to b's buffer.
// The returned error is always nil.
func (b *Buffer) WriteByte(v byte) error { return b.s.WriteByte(v) }

// WriteRune appends the UTF-8 encoding of Unicode code point r to b's buffer.
// It returns the length of r and a nil error.
func (b *Buffer) WriteRune(r rune) (int, error) { return b.s.WriteRune(r) }

// Write appends the contents of p to b's buffer.
// Write always returns len(p), nil.
func (b *Buffer) Write(p []byte) (int, error) { return b.s.Write(p) }

// WriteString appends the contents of s to b's buffer.
// It returns the length of s and a nil error.
func (b *Buffer) WriteString(s string) (int, error) { return b.s.WriteString(s) }

// String returns the accumulated string.
func (b *Buffer) String() string { return b.s.String() }
