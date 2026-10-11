package probe

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

const maxInflight = 32

// TCPAlive dials all ports concurrently. A successful connect or a refusal
// (RST) both prove the host is up. It returns on the first proof.
func TCPAlive(ctx context.Context, addr netip.Addr, ports []int, timeout time.Duration) (bool, time.Duration) {
	if len(ports) == 0 {
		return false, 0
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	start := time.Now()
	proof := make(chan struct{}, len(ports))
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			conn, err := dial(ctx, &d, target(addr, p))
			if err == nil {
				conn.Close()
				proof <- struct{}{}
				return
			}
			if isRefused(err) {
				proof <- struct{}{}
			}
		}(p)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-proof:
		return true, time.Since(start)
	case <-done:
		// A proof may have been sent just before the last goroutine finished.
		select {
		case <-proof:
			return true, time.Since(start)
		default:
			return false, 0
		}
	case <-ctx.Done():
		return false, 0
	}
}

// OpenPorts returns the sorted subset of ports that accept a TCP connection.
func OpenPorts(ctx context.Context, addr netip.Addr, ports []int, timeout time.Duration) []int {
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		open = []int{}
		sem  = make(chan struct{}, maxInflight)
	)
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			d := net.Dialer{Timeout: timeout}
			conn, err := dial(ctx, &d, target(addr, p))
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func target(addr netip.Addr, port int) string {
	return net.JoinHostPort(addr.String(), strconv.Itoa(port))
}
