//go:build darwin

package probe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var neighborTable = &macTable{load: loadRouteARP}

// loadRouteARP reads the IPv4 link-layer (ARP) entries from the routing
// table via sysctl NET_RT_FLAGS with RTF_LLINFO. An entry is confirmed when
// its rmx_expire is 0 (permanent) or still in the future; a stale entry
// lingers past its expiry until the kernel reaps it.
func loadRouteARP() map[netip.Addr]neighbor {
	out := make(map[netip.Addr]neighbor)
	b, err := route.FetchRIB(unix.AF_INET, route.RIBType(unix.NET_RT_FLAGS), unix.RTF_LLINFO)
	if err != nil {
		return out
	}
	now := time.Now().Unix()
	// x/net/route does not expose rt_metrics, so walk the raw messages and
	// parse each one on its own to keep the raw bytes next to the result.
	for len(b) >= 4 {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			break
		}
		raw := b[:l]
		b = b[l:]
		expire, ok := rtMsgExpire(raw)
		if !ok {
			continue
		}
		msgs, err := route.ParseRIB(route.RIBTypeRoute, raw)
		if err != nil || len(msgs) != 1 {
			continue
		}
		rm, ok := msgs[0].(*route.RouteMessage)
		if !ok || len(rm.Addrs) <= unix.RTAX_GATEWAY {
			continue
		}
		dst, ok := rm.Addrs[unix.RTAX_DST].(*route.Inet4Addr)
		if !ok {
			continue
		}
		gw, ok := rm.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok {
			continue
		}
		mac := usableMAC(gw.Addr)
		if mac == "" {
			continue
		}
		out[netip.AddrFrom4(dst.IP)] = neighbor{mac: mac, confirmed: expire == 0 || int64(expire) > now}
	}
	return out
}

func arpResolve(ctx context.Context, addr netip.Addr, timeout time.Duration) (string, bool) {
	return resolveViaTable(ctx, neighborTable, addr, timeout)
}
