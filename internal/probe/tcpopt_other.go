//go:build !windows

package probe

import (
	"syscall"
	"time"
)

// dialControl is only needed on Windows; see tcpopt_windows.go.
func dialControl(time.Time) func(network, address string, c syscall.RawConn) error {
	return nil
}
