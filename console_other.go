//go:build !windows

package main

// isDoubleClick is always false: macOS and Linux open a terminal for binaries.
func isDoubleClick() bool { return false }
