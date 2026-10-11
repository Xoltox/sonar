// Package target parses scan target specs and discovers local subnets.
package target

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxHostsDefault is the host cap (a /16) unless the caller forces more.
const MaxHostsDefault = 65536

// span is an inclusive range of IPv4 addresses as integers.
type span struct{ lo, hi uint32 }

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// prefixSpan returns the host span of a prefix: /0-/30 skip network and
// broadcast, /31 and /32 include everything.
func prefixSpan(p netip.Prefix) span {
	p = p.Masked()
	lo := addrToU32(p.Addr())
	hostBits := uint(32 - p.Bits())
	hi := lo | uint32((uint64(1)<<hostBits)-1)
	if p.Bits() <= 30 {
		lo++
		hi--
	}
	return span{lo, hi}
}

// mergeSpans sorts and merges overlapping or adjacent spans.
func mergeSpans(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo < in[j].lo })
	out := []span{in[0]}
	for _, s := range in[1:] {
		last := &out[len(out)-1]
		if uint64(s.lo) <= uint64(last.hi)+1 {
			if s.hi > last.hi {
				last.hi = s.hi
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

func countSpans(spans []span) uint64 {
	var n uint64
	for _, s := range spans {
		n += uint64(s.hi) - uint64(s.lo) + 1
	}
	return n
}

func expandSpans(spans []span) []netip.Addr {
	out := make([]netip.Addr, 0, countSpans(spans))
	for _, s := range spans {
		for v := uint64(s.lo); v <= uint64(s.hi); v++ {
			out = append(out, u32ToAddr(uint32(v)))
		}
	}
	return out
}

func parseIPv4(tok string) (netip.Addr, error) {
	a, err := netip.ParseAddr(tok)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", tok)
	}
	if a.Is6() && !a.Is4In6() {
		return netip.Addr{}, fmt.Errorf("IPv6 is not supported: %q", tok)
	}
	a = a.Unmap()
	if !a.Is4() {
		return netip.Addr{}, fmt.Errorf("not an IPv4 address: %q", tok)
	}
	return a, nil
}

func parseItem(item string) (span, error) {
	if strings.Contains(item, ":") {
		return span{}, fmt.Errorf("IPv6 is not supported: %q", item)
	}
	if strings.Contains(item, "/") {
		p, err := netip.ParsePrefix(item)
		if err != nil {
			return span{}, fmt.Errorf("invalid CIDR %q", item)
		}
		if !p.Addr().Is4() {
			return span{}, fmt.Errorf("IPv6 is not supported: %q", item)
		}
		return prefixSpan(p), nil
	}
	if i := strings.Index(item, "-"); i >= 0 {
		left, right := strings.TrimSpace(item[:i]), strings.TrimSpace(item[i+1:])
		start, err := parseIPv4(left)
		if err != nil {
			return span{}, fmt.Errorf("invalid range %q: %w", item, err)
		}
		var end netip.Addr
		if strings.Contains(right, ".") {
			end, err = parseIPv4(right)
			if err != nil {
				return span{}, fmt.Errorf("invalid range %q: %w", item, err)
			}
		} else {
			n, perr := strconv.Atoi(right)
			if perr != nil || n < 0 || n > 255 {
				return span{}, fmt.Errorf("invalid range end in %q", item)
			}
			b := start.As4()
			b[3] = byte(n)
			end = netip.AddrFrom4(b)
		}
		s, e := addrToU32(start), addrToU32(end)
		if s > e {
			return span{}, fmt.Errorf("range start is after end in %q", item)
		}
		return span{s, e}, nil
	}
	a, err := parseIPv4(item)
	if err != nil {
		return span{}, err
	}
	v := addrToU32(a)
	return span{v, v}, nil
}

func parseSpans(spec string) ([]span, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("empty target spec")
	}
	var spans []span
	for _, raw := range strings.Split(spec, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			return nil, fmt.Errorf("empty item in target spec %q", spec)
		}
		s, err := parseItem(item)
		if err != nil {
			return nil, err
		}
		spans = append(spans, s)
	}
	return spans, nil
}

// Parse parses one spec: a comma list of CIDR, short range, full range or
// single IPv4. The result is deduplicated and sorted ascending.
func Parse(spec string) ([]netip.Addr, error) {
	spans, err := parseSpans(spec)
	if err != nil {
		return nil, err
	}
	return expandSpans(mergeSpans(spans)), nil
}

// ParseAll parses every arg, merges, dedups and sorts. More than
// MaxHostsDefault hosts is an error unless force is set.
func ParseAll(args []string, force bool) ([]netip.Addr, error) {
	var all []span
	for _, arg := range args {
		spans, err := parseSpans(arg)
		if err != nil {
			return nil, err
		}
		all = append(all, spans...)
	}
	merged := mergeSpans(all)
	if n := countSpans(merged); n > MaxHostsDefault && !force {
		return nil, fmt.Errorf("targets expand to %d hosts, over the limit of %d; use --force to scan anyway", n, MaxHostsDefault)
	}
	return expandSpans(merged), nil
}
