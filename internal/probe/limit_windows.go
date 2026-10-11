//go:build windows

package probe

// RaiseFileLimit is a no-op on Windows; it reports an unknown (0) limit.
func RaiseFileLimit() (uint64, error) { return 0, nil }
