//go:build !windows

package output

import "os"

// ColorEnabled reports whether f is a terminal that can show ANSI colors.
func ColorEnabled(f *os.File) bool {
	if noColorEnv() || f == nil || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
