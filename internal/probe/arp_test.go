package probe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

const procNetARPGolden = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.20     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.21     0x1         0x0         11:22:33:44:55:66     *        eth0
192.168.1.30     0x1         0x2         00:00:00:00:00:00     *        eth0
192.168.1.40     0x1         0x6         0a:0b:0c:0d:0e:0f     *        eth0
`

func TestParseProcNetARP(t *testing.T) {
	m := parseProcNetARP(strings.NewReader(procNetARPGolden))
	if len(m) != 2 {
		t.Fatalf("got %d entries: %v", len(m), m)
	}
	if got := m[netip.MustParseAddr("192.168.1.1")]; got != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("complete entry = %q", got)
	}
	if got := m[netip.MustParseAddr("192.168.1.40")]; got != "0A:0B:0C:0D:0E:0F" {
		t.Errorf("flags 0x6 entry = %q", got)
	}
	for _, ip := range []string{"192.168.1.20", "192.168.1.21", "192.168.1.30"} {
		if _, ok := m[netip.MustParseAddr(ip)]; ok {
			t.Errorf("%s should be excluded", ip)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"aa:bb:cc:dd:ee:ff":  "AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff":  "AA:BB:CC:DD:EE:FF",
		"a:b:c:d:e:f":        "0A:0B:0C:0D:0E:0F",
		"0:1:2:3:4:5":        "00:01:02:03:04:05",
		"00:00:00:00:00:00":  "",
		"0:0:0:0:0:0":        "",
		"aa:bb:cc:dd:ee":     "",
		"aa:bb:cc:dd:ee:gg":  "",
		"aaa:bb:cc:dd:ee:ff": "",
		"":                   "",
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	if got := formatMAC([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x0a}); got != "DE:AD:BE:EF:00:0A" {
		t.Errorf("formatMAC = %q", got)
	}
	if got := formatMAC(nil); got != "" {
		t.Errorf("formatMAC(nil) = %q", got)
	}
}

func TestARPLoopback(t *testing.T) {
	start := time.Now()
	mac, ok := ARP(context.Background(), netip.MustParseAddr("127.0.0.1"), time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("ARP on loopback took %v", d)
	}
	t.Logf("loopback mac=%q ok=%v", mac, ok)
}

func TestARPGateway(t *testing.T) {
	gw := os.Getenv("SONAR_GATEWAY")
	if os.Getenv("SONAR_LIVE") != "1" || gw == "" {
		t.Skip("set SONAR_LIVE=1 and SONAR_GATEWAY=<default gateway ip>")
	}
	mac, ok := ARP(context.Background(), netip.MustParseAddr(gw), 3*time.Second)
	t.Logf("gateway %s mac=%q ok=%v", gw, mac, ok)
	if !ok {
		t.Fatal("gateway did not answer ARP")
	}
}

func TestNeighborTableLoads(t *testing.T) {
	m := neighborTable.load()
	for a, n := range m {
		if !a.Is4() || normalizeMAC(n.mac) != n.mac {
			t.Errorf("bad entry %v -> %+v", a, n)
		}
	}
	t.Logf("%d neighbor entries", len(m))
}

func TestCachedMACGateway(t *testing.T) {
	gw := os.Getenv("SONAR_GATEWAY")
	if os.Getenv("SONAR_LIVE") != "1" || gw == "" {
		t.Skip("set SONAR_LIVE=1 and SONAR_GATEWAY=<default gateway ip>")
	}
	if _, ok := ARP(context.Background(), netip.MustParseAddr(gw), 3*time.Second); !ok {
		t.Fatal("gateway did not answer ARP")
	}
	mac, ok := CachedMAC(netip.MustParseAddr(gw))
	t.Logf("gateway %s cached mac=%q ok=%v", gw, mac, ok)
	if !ok {
		t.Fatal("gateway missing from OS neighbor cache right after ARP")
	}
}

func TestMACTableCachedFallsBackToLastSeen(t *testing.T) {
	a := netip.MustParseAddr("10.1.2.3")
	entries := []map[netip.Addr]neighbor{
		{a: {mac: "AA:BB:CC:DD:EE:01", confirmed: false}}, // Stale
		{}, // Incomplete while re-resolving: no usable entry
	}
	i := 0
	tb := &macTable{load: func() map[netip.Addr]neighbor {
		m := entries[min(i, len(entries)-1)]
		i++
		return m
	}}
	if _, ok := tb.confirmed(a); ok {
		t.Fatal("stale entry must not count as confirmed")
	}
	time.Sleep(arpSnapshotTTL)
	mac, ok := tb.cached(a)
	if !ok || mac != "AA:BB:CC:DD:EE:01" {
		t.Fatalf("cached = %q, %v; want last seen MAC", mac, ok)
	}
	if _, ok := tb.cached(netip.MustParseAddr("10.1.2.4")); ok {
		t.Fatal("unknown address must miss")
	}
}

// ndmsgGolden builds one RTM_NEWNEIGH payload in native byte order.
func ndmsgGolden(family byte, state uint16, attrs ...[]byte) []byte {
	b := make([]byte, ndmsgLen)
	b[0] = family
	binary.NativeEndian.PutUint32(b[4:], 2) // ifindex
	binary.NativeEndian.PutUint16(b[8:], state)
	b[11] = 1 // NDA type unicast
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

func nlAttr(typ uint16, val []byte) []byte {
	b := make([]byte, 4, 4+len(val)+3)
	binary.NativeEndian.PutUint16(b[0:], uint16(4+len(val)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	b = append(b, val...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func TestParseNdmsg(t *testing.T) {
	dst := nlAttr(ndaDst, []byte{192, 168, 1, 7})
	mac := nlAttr(ndaLLAddr, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}) // padded to 8
	cases := []struct {
		name      string
		data      []byte
		ok        bool
		confirmed bool
	}{
		{"reachable", ndmsgGolden(afInet, nudReachable, dst, mac), true, true},
		{"permanent", ndmsgGolden(afInet, nudPermanent, dst, mac), true, true},
		{"stale", ndmsgGolden(afInet, 0x04, dst, mac), true, false},
		{"delay", ndmsgGolden(afInet, 0x08, dst, mac), true, false},
		{"probe", ndmsgGolden(afInet, 0x10, dst, mac), true, false},
		{"incomplete no lladdr", ndmsgGolden(afInet, 0x01, dst), false, false},
		{"failed zero mac", ndmsgGolden(afInet, 0x20, dst, nlAttr(ndaLLAddr, make([]byte, 6))), false, false},
		{"broadcast mac", ndmsgGolden(afInet, nudReachable, dst, nlAttr(ndaLLAddr, []byte{255, 255, 255, 255, 255, 255})), false, false},
		{"multicast mac", ndmsgGolden(afInet, nudReachable, dst, nlAttr(ndaLLAddr, []byte{1, 0, 0x5e, 0, 0, 1})), false, false},
		{"ipv6 family", ndmsgGolden(10, nudReachable, dst, mac), false, false},
		{"truncated", ndmsgGolden(afInet, nudReachable, dst, mac)[:15], false, false},
		{"short header", []byte{2, 0, 0}, false, false},
	}
	for _, tc := range cases {
		a, n, ok := parseNdmsg(tc.data)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if a != netip.MustParseAddr("192.168.1.7") || n.mac != "AA:BB:CC:DD:EE:01" || n.confirmed != tc.confirmed {
			t.Errorf("%s: got %v %+v", tc.name, a, n)
		}
	}
}

func TestRtMsgExpire(t *testing.T) {
	msg := make([]byte, 92)
	binary.NativeEndian.PutUint32(msg[48:], 1700000000)
	if v, ok := rtMsgExpire(msg); !ok || v != 1700000000 {
		t.Errorf("rtMsgExpire = %d, %v", v, ok)
	}
	if _, ok := rtMsgExpire(msg[:60]); ok {
		t.Error("short message must fail")
	}
}
