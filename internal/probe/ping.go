package probe

import (
	"context"
	"net/netip"
	"time"
)

// Ping sends one ICMP echo and waits for the reply. ok=false,err=nil means no reply.
// err != nil means ICMP is unavailable on this system (e.g. permission denied); callers then rely on TCP/ARP.
func Ping(ctx context.Context, addr netip.Addr, timeout time.Duration) (ok bool, rtt time.Duration, err error) {
	return ping(ctx, addr.Unmap(), timeout)
}

// PingAvailable reports whether unprivileged ICMP works here. It is checked
// once by opening and closing the socket. hint is a one-line user hint when
// unavailable.
func PingAvailable() (ok bool, hint string) {
	return pingAvailable()
}
