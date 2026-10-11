package output

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Xoltox/sonar/internal/scan"
)

type tableWriter struct {
	w     io.Writer
	color bool
	rows  []scan.Result
}

// NewTable buffers results and prints them sorted by IP as an aligned table on Close.
func NewTable(w io.Writer, color bool) Writer {
	return &tableWriter{w: w, color: color}
}

func (t *tableWriter) Write(r scan.Result) error {
	t.rows = append(t.rows, r)
	return nil
}

func formatRTT(r scan.Result) string {
	if !r.Alive {
		return "-"
	}
	if r.RTT < time.Millisecond {
		return "<1ms"
	}
	return strconv.FormatInt(r.RTT.Milliseconds(), 10) + "ms"
}

func joinPorts(p []int, sep string) string {
	s := make([]string, len(p))
	for i, n := range p {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, sep)
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-3]) + "..."
}

type column struct {
	name   string
	always bool
	get    func(scan.Result) string
}

var columns = []column{
	{"IP", true, func(r scan.Result) string { return r.IP.String() }},
	{"STATUS", true, func(r scan.Result) string {
		if r.Alive {
			return "up"
		}
		return "down"
	}},
	{"RTT", true, formatRTT},
	{"HOSTNAME", false, func(r scan.Result) string { return r.Hostname }},
	{"MAC", false, func(r scan.Result) string { return r.MAC }},
	{"VENDOR", false, func(r scan.Result) string { return r.Vendor }},
	{"PORTS", false, func(r scan.Result) string { return joinPorts(r.Ports, ",") }},
	{"HTTP TITLE", false, func(r scan.Result) string { return truncate(r.HTTPTitle, 40) }},
}

func (t *tableWriter) Close() error {
	sort.SliceStable(t.rows, func(i, j int) bool { return t.rows[i].IP.Less(t.rows[j].IP) })

	cells := make([][]string, len(t.rows))
	for i, r := range t.rows {
		cells[i] = make([]string, len(columns))
		for j, c := range columns {
			cells[i][j] = c.get(r)
		}
	}
	var keep []int
	widths := make([]int, len(columns))
	for j, c := range columns {
		used := c.always
		w := utf8.RuneCountInString(c.name)
		for i := range cells {
			if cells[i][j] != "" {
				used = true
			}
			if n := utf8.RuneCountInString(cells[i][j]); n > w {
				w = n
			}
		}
		widths[j] = w
		if used {
			keep = append(keep, j)
		}
	}

	var b strings.Builder
	emit := func(j int, text, style string, last bool) {
		if style != "" && t.color {
			b.WriteString(style + text + ansiReset)
		} else {
			b.WriteString(text)
		}
		if !last {
			b.WriteString(strings.Repeat(" ", widths[j]-utf8.RuneCountInString(text)+2))
		}
	}
	for k, j := range keep {
		emit(j, columns[j].name, ansiBold, k == len(keep)-1)
	}
	b.WriteByte('\n')
	for i := range cells {
		for k, j := range keep {
			style := ""
			if j == 1 {
				style = ansiDim
				if t.rows[i].Alive {
					style = ansiGreen
				}
			}
			emit(j, cells[i][j], style, k == len(keep)-1)
		}
		b.WriteByte('\n')
	}
	_, err := fmt.Fprint(t.w, b.String())
	return err
}
