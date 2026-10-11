package probe

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DefaultPorts is the port list scanned by default.
var DefaultPorts = []int{21, 22, 23, 53, 80, 135, 139, 443, 445, 3389, 5900, 8080, 8443}

// AlivePorts are the ports probed to decide whether a host is up.
var AlivePorts = []int{445, 80, 22, 3389, 443, 139}

// ParsePorts parses "none", "default", or a comma list of ports and ranges.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "none":
		return []int{}, nil
	case "default":
		return append([]int{}, DefaultPorts...), nil
	}
	seen := make(map[int]bool)
	out := []int{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", s)
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
			if b < a {
				return nil, fmt.Errorf("invalid range %q", part)
			}
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", n)
	}
	return n, nil
}
