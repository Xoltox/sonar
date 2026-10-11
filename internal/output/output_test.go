package output

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Xoltox/sonar/internal/scan"
)

func sample() []scan.Result {
	return []scan.Result{
		{IP: netip.MustParseAddr("10.0.0.10"), Alive: true, AliveBy: "tcp", RTT: 3 * time.Millisecond, Hostname: "box", Ports: []int{22, 80}},
		{IP: netip.MustParseAddr("10.0.0.2"), Alive: true, AliveBy: "icmp", RTT: 200 * time.Microsecond},
	}
}

func TestTable(t *testing.T) {
	var buf bytes.Buffer
	w := NewTable(&buf, false)
	for _, r := range sample() {
		w.Write(r)
	}
	w.Close()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines: %q", lines)
	}
	if !strings.HasPrefix(lines[0], "IP") || !strings.Contains(lines[0], "HOSTNAME") || !strings.Contains(lines[0], "PORTS") {
		t.Errorf("header: %q", lines[0])
	}
	for _, absent := range []string{"MAC", "VENDOR", "HTTP TITLE"} {
		if strings.Contains(lines[0], absent) {
			t.Errorf("column %s should be omitted", absent)
		}
	}
	if !strings.HasPrefix(lines[1], "10.0.0.2 ") || !strings.HasPrefix(lines[2], "10.0.0.10") {
		t.Errorf("sort order: %q", lines)
	}
	if !strings.Contains(lines[1], "<1ms") || !strings.Contains(lines[2], "3ms") {
		t.Errorf("rtt: %q", lines)
	}
}

func TestTableColor(t *testing.T) {
	var buf bytes.Buffer
	w := NewTable(&buf, true)
	for _, r := range sample() {
		w.Write(r)
	}
	w.Close()
	if !strings.Contains(buf.String(), ansiGreen+"up"+ansiReset) {
		t.Errorf("missing green up: %q", buf.String())
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	NewJSON(&buf).Close()
	var out []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil || len(out) != 0 {
		t.Fatalf("empty: %q %v", buf.String(), err)
	}
	buf.Reset()
	w := NewJSON(&buf)
	for _, r := range sample() {
		w.Write(r)
	}
	w.Close()
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil || len(out) != 2 {
		t.Fatalf("two: %q %v", buf.String(), err)
	}
	if out[0]["ip"] != "10.0.0.10" {
		t.Errorf("ip: %v", out[0]["ip"])
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSV(&buf)
	w.Write(sample()[0])
	w.Close()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if lines[0] != "ip,status,alive_by,rtt_ms,hostname,name_src,mac,vendor,ports,http_title" {
		t.Errorf("header: %q", lines[0])
	}
	if lines[1] != "10.0.0.10,up,tcp,3,box,,,,22;80," {
		t.Errorf("row: %q", lines[1])
	}
}
