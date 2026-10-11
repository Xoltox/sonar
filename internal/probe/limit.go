package probe

import (
	"context"
	"sync"
)

const (
	defaultMaxDials = 512
	// maxBlockingCalls bounds OS threads parked in uncancellable blocking
	// calls (SendARP, IcmpSendEcho2 on Windows). These hold no socket, so
	// they get their own limiter and never starve TCP dials.
	maxBlockingCalls = 1024
	// maxARPCalls bounds SendARP threads separately: SendARP on a dead host
	// blocks about 3s, and those stragglers must never delay ICMP.
	maxARPCalls = 256
)

var (
	dialMu  sync.RWMutex
	dialSem = make(chan struct{}, defaultMaxDials)

	// aliveSem caps the alive-probe share of the socket pool at 3/4 so a
	// burst of dials to dead hosts can never delay port scans of live ones.
	aliveSem    = make(chan struct{}, defaultMaxDials*3/4)
	blockingSem = make(chan struct{}, maxBlockingCalls)
	arpSem      = make(chan struct{}, maxARPCalls)
)

// SetMaxDials resizes the global socket semaphore. Call it once at startup,
// before any probe runs.
func SetMaxDials(n int) {
	if n < 1 {
		n = 1
	}
	dialMu.Lock()
	dialSem = make(chan struct{}, n)
	aliveSem = make(chan struct{}, max(1, n*3/4))
	dialMu.Unlock()
}

func socketSem() chan struct{} {
	dialMu.RLock()
	defer dialMu.RUnlock()
	return dialSem
}

func aliveQuota() chan struct{} {
	dialMu.RLock()
	defer dialMu.RUnlock()
	return aliveSem
}

// acquireAlive takes a socket slot for an alive-probe dial: one from the
// alive quota first, then one from the global pool.
func acquireAlive(ctx context.Context) (release func(), err error) {
	rq, err := acquireFrom(ctx, aliveQuota())
	if err != nil {
		return nil, err
	}
	rg, err := acquire(ctx)
	if err != nil {
		rq()
		return nil, err
	}
	return func() { rg(); rq() }, nil
}

// tryAcquireAlive is acquireAlive without waiting.
func tryAcquireAlive() (release func(), ok bool) {
	q := aliveQuota()
	select {
	case q <- struct{}{}:
	default:
		return nil, false
	}
	rg, ok := tryAcquire()
	if !ok {
		<-q
		return nil, false
	}
	return func() { rg(); <-q }, true
}

// acquire takes a slot from the global socket semaphore. It returns
// ctx.Err() if ctx is done first. The caller must call release exactly once.
func acquire(ctx context.Context) (release func(), err error) {
	return acquireFrom(ctx, socketSem())
}

// tryAcquire takes a socket slot only if one is free right now.
func tryAcquire() (release func(), ok bool) {
	sem := socketSem()
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, true
	default:
		return nil, false
	}
}

// acquireBlocking takes a slot for an uncancellable blocking OS call.
func acquireBlocking(ctx context.Context) (release func(), err error) {
	return acquireFrom(ctx, blockingSem)
}

func acquireFrom(ctx context.Context, sem chan struct{}) (func(), error) {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return func() { <-sem }, nil
}

// acquireARP takes a slot for a blocking SendARP call.
func acquireARP(ctx context.Context) (release func(), err error) {
	return acquireFrom(ctx, arpSem)
}
