package probe

import (
	"context"
	"net"
	"sync"
)

const defaultMaxDials = 512

var (
	dialMu  sync.RWMutex
	dialSem = make(chan struct{}, defaultMaxDials)
)

// SetMaxDials resizes the global dial semaphore. Call it once at startup,
// before any probe runs.
func SetMaxDials(n int) {
	if n < 1 {
		n = 1
	}
	dialMu.Lock()
	dialSem = make(chan struct{}, n)
	dialMu.Unlock()
}

// dial runs a TCP dial while holding a slot in the global semaphore. It
// returns early with ctx.Err() if ctx is done before a slot frees up.
func dial(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	dialMu.RLock()
	sem := dialSem
	dialMu.RUnlock()
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-sem }()
	return d.DialContext(ctx, "tcp", addr)
}
