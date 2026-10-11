//go:build windows

package probe

import (
	"errors"
	"syscall"
)

const wsaeconnrefused = syscall.Errno(10061)

// isRefused reports whether err is a TCP connection refused (RST) error.
func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var en syscall.Errno
	if errors.As(err, &en) {
		return en == wsaeconnrefused
	}
	return false
}
