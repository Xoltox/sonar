package probe

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	arpSnapshotTTL = 40 * time.Millisecond
	arpPollEvery   = 50 * time.Millisecond
	cachedMaxAge   = 5 * time.Millisecond
)

// ARP resolves addr's MAC on the local link. Only meaningful for addresses on
// a directly attached subnet. ok is true with mac formatted
// "AA:BB:CC:DD:EE:FF" when the host answered ARP. Incomplete or failed
// entries and all-zero MACs give ok=false.
func ARP(ctx context.Context, addr netip.Addr, timeout time.Duration) (mac string, ok bool) {
	addr = addr.Unmap()
	if !addr.Is4() || timeout <= 0 {
		return "", false
	}
	return arpResolve(ctx, addr, timeout)
}

// CachedMAC reads addr's MAC from the OS neighbor (ARP) cache without
// sending anything. Use it for a host already known to be up: talking to it
// has just filled the cache.
func CachedMAC(addr netip.Addr) (string, bool) {
	addr = addr.Unmap()
	if !addr.Is4() {
		return "", false
	}
	return neighborTable.cached(addr)
}

// formatMAC renders b as uppercase colon-separated hex.
func formatMAC(b []byte) string {
	const hexdigits = "0123456789ABCDEF"
	if len(b) == 0 {
		return ""
	}
	out := make([]byte, 0, len(b)*3-1)
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexdigits[v>>4], hexdigits[v&0x0f])
	}
	return string(out)
}

// normalizeMAC accepts "a:b:c:d:e:f" or "aa-bb-cc-dd-ee-ff" style input and
// returns the uppercase two-digit colon form, or "" if the input is invalid
// or all zero.
func normalizeMAC(s string) string {
	s = strings.TrimSpace(s)
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == '-' })
	if len(parts) != 6 {
		return ""
	}
	b := make([]byte, 6)
	nonzero := false
	for i, p := range parts {
		if len(p) < 1 || len(p) > 2 {
			return ""
		}
		v, ok := parseHex(p)
		if !ok {
			return ""
		}
		b[i] = byte(v)
		if v != 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return ""
	}
	return formatMAC(b)
}

func parseHex(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		v = v<<4 | d
	}
	return v, true
}

// parseProcNetARP parses the Linux /proc/net/arp format. Only complete
// entries (ATF_COM flag 0x2) with a non-zero MAC are returned.
func parseProcNetARP(r io.Reader) map[netip.Addr]string {
	out := make(map[netip.Addr]string)
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		flags, ok := parseHex(strings.TrimPrefix(strings.TrimPrefix(f[2], "0x"), "0X"))
		if !ok || flags&0x2 == 0 {
			continue
		}
		mac := normalizeMAC(f[3])
		if mac == "" {
			continue
		}
		out[ip.Unmap()] = mac
	}
	return out
}

// neighbor is one OS neighbor-cache entry with a usable MAC. confirmed is
// false for entries the OS has not verified recently (Windows Stale, Delay,
// Probe); those still name the right MAC for a host known to be up, but do
// not prove it is up.
type neighbor struct {
	mac       string
	confirmed bool
}

// macTable is a shared, rate-limited snapshot of the OS neighbor table so
// hundreds of concurrent pollers do not each re-read it.
type macTable struct {
	load func() map[netip.Addr]neighbor

	mu   sync.Mutex
	at   time.Time
	snap map[netip.Addr]neighbor
	// seen keeps the last MAC each address had in any snapshot. Windows
	// clears a Stale entry's MAC while it re-resolves (e.g. on SendARP), so
	// a host can answer ping while its current entry is Incomplete.
	seen map[netip.Addr]string
}

// lookup returns addr's entry from a snapshot at most maxAge old.
func (t *macTable) lookup(addr netip.Addr, maxAge time.Duration) (neighbor, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.snap == nil || time.Since(t.at) >= maxAge {
		t.snap = t.load()
		t.at = time.Now()
		if t.seen == nil {
			t.seen = make(map[netip.Addr]string)
		}
		for a, n := range t.snap {
			t.seen[a] = n.mac
		}
	}
	n, ok := t.snap[addr]
	return n, ok
}

func (t *macTable) lastSeen(addr netip.Addr) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	mac, ok := t.seen[addr]
	return mac, ok
}

// confirmed returns addr's MAC only for a confirmed entry.
func (t *macTable) confirmed(addr netip.Addr) (string, bool) {
	n, ok := t.lookup(addr, arpSnapshotTTL)
	if !ok || !n.confirmed {
		return "", false
	}
	return n.mac, true
}

// cached returns addr's MAC from any usable entry. A miss is retried with a
// fresh read since the caller has usually just talked to the host, then
// falls back to the last MAC seen for addr during this run.
func (t *macTable) cached(addr netip.Addr) (string, bool) {
	n, ok := t.lookup(addr, arpSnapshotTTL)
	if !ok {
		n, ok = t.lookup(addr, cachedMaxAge)
	}
	if ok {
		return n.mac, true
	}
	return t.lastSeen(addr)
}

// unconfirmedAll marks every entry of a plain addr->MAC map unconfirmed:
// the source (a cache dump without state) says the MAC is known, not that
// the host is up.
func unconfirmedAll(m map[netip.Addr]string) map[netip.Addr]neighbor {
	out := make(map[netip.Addr]neighbor, len(m))
	for a, mac := range m {
		out[a] = neighbor{mac: mac}
	}
	return out
}

// usableMAC returns the formatted MAC for a 6-byte hardware address, or ""
// for all-zero, broadcast and multicast addresses.
func usableMAC(b []byte) string {
	if len(b) != 6 || isBroadcastMAC(b) || b[0]&1 != 0 {
		return ""
	}
	return normalizeMAC(formatMAC(b))
}

func isBroadcastMAC(b []byte) bool {
	for _, v := range b {
		if v != 0xff {
			return false
		}
	}
	return true
}

// Linux neighbor (ndmsg) constants.
const (
	ndmsgLen     = 12 // family u8, pad u8, pad u16, ifindex i32, state u16, flags u8, type u8
	ndaDst       = 1
	ndaLLAddr    = 2
	nudReachable = 0x02
	nudPermanent = 0x80
	afInet       = 2
)

// parseNdmsg parses the payload of one RTM_NEWNEIGH netlink message (the
// bytes after the nlmsghdr) in native byte order. Only IPv4 entries with a
// usable MAC are returned. confirmed is true for NUD_REACHABLE and
// NUD_PERMANENT; stale, delay and probe entries are not proof of life.
func parseNdmsg(data []byte) (addr netip.Addr, n neighbor, ok bool) {
	if len(data) < ndmsgLen || data[0] != afInet {
		return netip.Addr{}, neighbor{}, false
	}
	state := binary.NativeEndian.Uint16(data[8:10])
	var dst, lladdr []byte
	for attrs := data[ndmsgLen:]; len(attrs) >= 4; {
		l := int(binary.NativeEndian.Uint16(attrs[0:2]))
		typ := binary.NativeEndian.Uint16(attrs[2:4]) &^ 0xc000 // strip NLA_F_* flags
		if l < 4 || l > len(attrs) {
			break
		}
		switch typ {
		case ndaDst:
			dst = attrs[4:l]
		case ndaLLAddr:
			lladdr = attrs[4:l]
		}
		next := (l + 3) &^ 3
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	if len(dst) != 4 {
		return netip.Addr{}, neighbor{}, false
	}
	mac := usableMAC(lladdr)
	if mac == "" {
		return netip.Addr{}, neighbor{}, false
	}
	var a4 [4]byte
	copy(a4[:], dst)
	return netip.AddrFrom4(a4), neighbor{mac: mac, confirmed: state&(nudReachable|nudPermanent) != 0}, true
}

// rtMsgExpire returns rmx_expire from a raw BSD rt_msghdr as dumped by the
// darwin routing sysctl. Layout (darwin amd64 and arm64 share it): the header
// is 92 bytes, rt_metrics starts at offset 36 and rmx_expire (int32) is its
// fourth field, at offset 36+12 = 48. It is an absolute unix time in seconds,
// or 0 for a permanent entry.
func rtMsgExpire(msg []byte) (int32, bool) {
	const off = 48
	if len(msg) < 92 {
		return 0, false
	}
	return int32(binary.NativeEndian.Uint32(msg[off:])), true
}

// resolveViaTable checks the table, nudges the kernel with a UDP datagram to
// the discard port so it ARPs, then polls the table until the deadline.
func resolveViaTable(ctx context.Context, t *macTable, addr netip.Addr, timeout time.Duration) (string, bool) {
	if mac, ok := t.confirmed(addr); ok {
		return mac, true
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	triggerARP(ctx, addr)
	tick := time.NewTicker(arpPollEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", false
		case <-tick.C:
			if mac, ok := t.confirmed(addr); ok {
				return mac, true
			}
		}
	}
}

// triggerARP sends one UDP datagram to addr:9 so the kernel resolves the
// neighbor. Errors are ignored; the poll decides the outcome.
func triggerARP(ctx context.Context, addr netip.Addr) {
	release, err := acquire(ctx)
	if err != nil {
		return
	}
	defer release()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 9)))
	if err != nil {
		return
	}
	_, _ = c.Write([]byte{0})
	_ = c.Close()
}
