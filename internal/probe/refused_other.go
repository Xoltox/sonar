//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

// isRefused reports whether err is a TCP connection refused (RST) error.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
