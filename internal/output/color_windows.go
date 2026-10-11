//go:build windows

package output

import (
	"os"

	"golang.org/x/sys/windows"
)

// ColorEnabled reports whether f is a console that can show ANSI colors.
func ColorEnabled(f *os.File) bool {
	if noColorEnv() || f == nil {
		return false
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
