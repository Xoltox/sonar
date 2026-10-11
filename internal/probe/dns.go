package probe

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ReverseDNS returns the first PTR name for addr without the trailing dot,
// or "" (timeout, NXDOMAIN, error).
func ReverseDNS(ctx context.Context, addr netip.Addr, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan []string, 1)
	go func() {
		names, _ := net.DefaultResolver.LookupAddr(ctx, addr.String())
		ch <- names
	}()

	var names []string
	select {
	case names = <-ch:
	case <-ctx.Done():
		return ""
	}
	for _, n := range names {
		n = strings.TrimSuffix(n, ".")
		if n == "" || n == addr.String() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(n), ".in-addr.arpa") {
			continue
		}
		return n
	}
	return ""
}
