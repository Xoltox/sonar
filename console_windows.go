package main

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// isDoubleClick reports whether sonar is the only process attached to its
// console, i.e. it was started from Explorer rather than from a terminal.
func isDoubleClick() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if n != 1 || os.Getenv("CI") != "" {
		return false
	}
	// A real console must back both stdin and stdout; scheduled tasks,
	// services and redirected launches fail one of these.
	var mode uint32
	if windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) != nil {
		return false
	}
	if windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode) != nil {
		return false
	}
	return true
}
