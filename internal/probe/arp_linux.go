//go:build linux

package probe

import (
	"context"
	"net/netip"
	"os"
	"syscall"
	"time"
)

const procNetARP = "/proc/net/arp"

// neighborTable reads neighbor state over netlink (no privileges needed), so
// only NUD_REACHABLE and NUD_PERMANENT entries prove a host is up. If netlink
// fails it falls back to /proc/net/arp, which has no state: those entries
// only supply MACs.
var neighborTable = &macTable{load: func() map[netip.Addr]neighbor {
	if m, ok := loadNetlinkNeigh(); ok {
		return m
	}
	f, err := os.Open(procNetARP)
	if err != nil {
		return map[netip.Addr]neighbor{}
	}
	defer f.Close()
	return unconfirmedAll(parseProcNetARP(f))
}}

// loadNetlinkNeigh dumps the IPv4 neighbor table with RTM_GETNEIGH.
func loadNetlinkNeigh() (map[netip.Addr]neighbor, bool) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETNEIGH, syscall.AF_INET)
	if err != nil {
		return nil, false
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, false
	}
	out := make(map[netip.Addr]neighbor)
	for _, m := range msgs {
		if m.Header.Type != syscall.RTM_NEWNEIGH {
			continue
		}
		if a, n, ok := parseNdmsg(m.Data); ok {
			out[a] = n
		}
	}
	return out, true
}

func arpResolve(ctx context.Context, addr netip.Addr, timeout time.Duration) (string, bool) {
	return resolveViaTable(ctx, neighborTable, addr, timeout)
}
