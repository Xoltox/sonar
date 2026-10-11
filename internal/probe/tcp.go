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

const (
	maxInflight = 32
	// maxAttempts is how many overlapping connects one port may get. Extra
	// attempts start every timeout/maxAttempts+1 while earlier ones are still
	// pending, and only if a socket slot is free right now. They stand in
	// for the OS SYN retransmit (1s on Windows, Linux and macOS), which is
	// later than the default 800ms timeout, so one lost SYN or SYN-ACK
	// (common on Wi-Fi while hundreds of ARP broadcasts are in the air)
	// no longer hides an open port.
	maxAttempts = 3
	// minStagger disables extra attempts for very short timeouts.
	minStagger = 50 * time.Millisecond
)

type dialResult struct {
	conn net.Conn
	err  error
}

// dialPort connects to addr:port. timeout counts from when the first socket
// slot is obtained, so waiting for a slot never turns into a false negative.
// It returns as soon as one attempt connects or is refused.
func dialPort(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) (net.Conn, error) {
	return dialPortWith(ctx, addr, port, timeout, acquire, tryAcquire)
}

// dialPortWith is dialPort with explicit slot acquisition, so alive probes
// can draw from the capped alive quota.
func dialPortWith(ctx context.Context, addr netip.Addr, port int, timeout time.Duration,
	acquire func(context.Context) (func(), error), tryAcquire func() (func(), bool)) (net.Conn, error) {
	release, err := acquire(ctx)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	dst := target(addr, port)
	results := make(chan dialResult, maxAttempts)
	launch := func(release func()) {
		go func() {
			defer release()
			d := net.Dialer{Deadline: deadline, Control: dialControl(deadline)}
			c, err := d.DialContext(dctx, "tcp", dst)
			results <- dialResult{c, err}
		}()
	}
	launch(release)
	launched, got := 1, 0

	var tick <-chan time.Time
	if stagger := timeout / (maxAttempts + 1); stagger >= minStagger {
		t := time.NewTicker(stagger)
		defer t.Stop()
		tick = t.C
	}

	// finish closes connections from attempts still in flight. Their
	// goroutines see dctx cancelled (deferred above) and exit promptly.
	finish := func(pending int) {
		if pending == 0 {
			return
		}
		go func() {
			for i := 0; i < pending; i++ {
				if r := <-results; r.conn != nil {
					r.conn.Close()
				}
			}
		}()
	}

	var lastErr error
	for {
		select {
		case r := <-results:
			got++
			if r.err == nil || isRefused(r.err) {
				finish(launched - got)
				return r.conn, r.err
			}
			lastErr = r.err
			if got == launched {
				// Nothing pending: either the deadline passed or the
				// connect failed outright (unreachable); retrying won't help.
				return nil, lastErr
			}
		case <-tick:
			if launched < maxAttempts {
				if rel, ok := tryAcquire(); ok {
					launch(rel)
					launched++
				}
			}
		}
	}
}

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
			conn, err := dialPortWith(ctx, addr, p, timeout, acquireAlive, tryAcquireAlive)
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
			conn, err := dialPort(ctx, addr, p, timeout)
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
