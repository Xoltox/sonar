//go:build linux || darwin

package probe

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// RaiseFileLimit lifts the soft RLIMIT_NOFILE to the hard limit (capped at
// 10240 on macOS) and returns the resulting soft limit.
func RaiseFileLimit() (uint64, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return 0, err
	}
	target := lim.Max
	if runtime.GOOS == "darwin" && target > 10240 {
		target = 10240
	}
	if target > lim.Cur {
		next := unix.Rlimit{Cur: target, Max: lim.Max}
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &next); err != nil {
			return uint64(lim.Cur), err
		}
		return uint64(target), nil
	}
	return uint64(lim.Cur), nil
}
