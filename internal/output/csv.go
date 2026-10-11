package output

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"

	"github.com/Xoltox/sonar/internal/scan"
)

type csvWriter struct {
	w       *csv.Writer
	started bool
}

// NewCSV writes a header and one row per result.
func NewCSV(w io.Writer) Writer {
	return &csvWriter{w: csv.NewWriter(w)}
}

func (c *csvWriter) header() error {
	if c.started {
		return nil
	}
	c.started = true
	return c.w.Write([]string{"ip", "status", "alive_by", "rtt_ms", "hostname", "name_src", "mac", "vendor", "ports", "http_title"})
}

func (c *csvWriter) Write(r scan.Result) error {
	if err := c.header(); err != nil {
		return err
	}
	status := "down"
	if r.Alive {
		status = "up"
	}
	ms := strconv.FormatFloat(float64(r.RTT.Microseconds())/1000, 'f', 1, 64)
	ms = strings.TrimSuffix(ms, ".0")
	return c.w.Write([]string{r.IP.String(), status, r.AliveBy, ms, r.Hostname, r.NameSrc, r.MAC, r.Vendor, joinPorts(r.Ports, ";"), r.HTTPTitle})
}

func (c *csvWriter) Close() error {
	if err := c.header(); err != nil {
		return err
	}
	c.w.Flush()
	return c.w.Error()
}
