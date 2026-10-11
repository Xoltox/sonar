package scan

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/target"
)

// Options controls a scan.
type Options struct {
	Timeout     time.Duration // per probe
	Concurrency int           // worker goroutines
	Ports       []int         // stage-2 port scan; empty => skip
	Locals      []target.Local
}

// AliveProbe returns ok=true with a method name ("tcp", later "icmp", "arp")
// and rtt if it proves the host is up.
type AliveProbe func(ctx context.Context, addr netip.Addr, o Options) (ok bool, method string, rtt time.Duration)

// Enricher fills fields of r for an alive host. Each enricher receives its own
// copy of the Result and must only write the fields it owns; the scanner merges
// the non-zero fields of every copy into the final Result.
type Enricher func(ctx context.Context, r *Result, o Options)

// aliveProbes and enrichers are the registration lists. Later waves add one line each.
var aliveProbes = []AliveProbe{
	tcpAlive,
}

var enrichers = []Enricher{
	portScan,
}

func tcpAlive(ctx context.Context, addr netip.Addr, o Options) (bool, string, time.Duration) {
	ok, rtt := probe.TCPAlive(ctx, addr, probe.AlivePorts, o.Timeout)
	return ok, "tcp", rtt
}

func portScan(ctx context.Context, r *Result, o Options) {
	if len(o.Ports) == 0 {
		return
	}
	r.Ports = probe.OpenPorts(ctx, r.IP, o.Ports, o.Timeout)
}

// Run scans targets and emits one Result per host (dead ones too). The channel
// closes when all hosts are done or ctx is cancelled.
func Run(ctx context.Context, targets []netip.Addr, o Options) <-chan Result {
	out := make(chan Result)
	workers := o.Concurrency
	if workers <= 0 {
		workers = 256
	}
	if workers > len(targets) {
		workers = len(targets)
	}

	jobs := make(chan netip.Addr)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range jobs {
				r := scanHost(ctx, addr, o)
				select {
				case out <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(out)
		defer wg.Wait()
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func scanHost(ctx context.Context, addr netip.Addr, o Options) Result {
	r := Result{IP: addr}
	if ctx.Err() != nil {
		return r
	}

	// Stage 1: all alive probes in parallel, first success wins.
	pctx, cancel := context.WithCancel(ctx)
	type hit struct {
		method string
		rtt    time.Duration
	}
	hits := make(chan hit, len(aliveProbes))
	var pwg sync.WaitGroup
	for _, p := range aliveProbes {
		pwg.Add(1)
		go func(p AliveProbe) {
			defer pwg.Done()
			if ok, method, rtt := p(pctx, addr, o); ok {
				hits <- hit{method, rtt}
				cancel()
			}
		}(p)
	}
	pwg.Wait()
	cancel()
	close(hits)
	if h, ok := <-hits; ok {
		r.Alive = true
		r.AliveBy = h.method
		r.RTT = h.rtt
	}
	if !r.Alive || ctx.Err() != nil {
		return r
	}

	// Stage 2: enrichers in parallel, each on its own copy, then merged.
	copies := make([]Result, len(enrichers))
	var ewg sync.WaitGroup
	for i, e := range enrichers {
		copies[i] = r
		ewg.Add(1)
		go func(i int, e Enricher) {
			defer ewg.Done()
			e(ctx, &copies[i], o)
		}(i, e)
	}
	ewg.Wait()
	for _, c := range copies {
		merge(&r, c)
	}
	return r
}

// merge copies non-zero enrichment fields of src into dst.
func merge(dst *Result, src Result) {
	if src.Hostname != "" {
		dst.Hostname = src.Hostname
		dst.NameSrc = src.NameSrc
	}
	if src.MAC != "" {
		dst.MAC = src.MAC
	}
	if src.Vendor != "" {
		dst.Vendor = src.Vendor
	}
	if len(src.Ports) > 0 {
		dst.Ports = src.Ports
	}
	if src.HTTPTitle != "" {
		dst.HTTPTitle = src.HTTPTitle
	}
}
