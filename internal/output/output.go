// Package output renders scan results as a table, JSON or CSV.
package output

import "github.com/Xoltox/sonar/internal/scan"

// Writer receives results and flushes them on Close.
type Writer interface {
	Write(r scan.Result) error
	Close() error
}
