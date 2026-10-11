package scan

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/target"
)

// debug prints per-host stage timings to stderr (SONAR_DEBUG=1).
var debug = os.Getenv("SONAR_DEBUG") == "1"

// Options controls a scan.
type Options struct {
	Timeout     time.Duration // per probe
	Concurrency int           // worker goroutines
	Ports       []int         // stage-2 port scan; empty => skip
	Locals      []target.Local
}

// localAliveTimeout caps the TCP alive probe on directly attached subnets.
const localAliveTimeout = 400 * time.Millisecond

// Proof is what an alive probe learned.
type Proof struct {
	Method string // "icmp" | "tcp" | "arp"
	RTT    time.Duration
	MAC    string
}

// AliveProbe returns a Proof and ok=true if it proves the host is up.
type AliveProbe func(ctx context.Context, addr netip.Addr, o Options) (Proof, bool)

// Enricher fills fields of r for an alive host. Each enricher receives its own
// copy of the Result and must only write the fields it owns; the scanner merges
// the non-zero fields of every copy into the final Result.
type Enricher func(ctx context.Context, r *Result, o Options)

// aliveProbes and enrichers are the registration lists. Later waves add one line each.
var aliveProbes = []AliveProbe{
	icmpAlive,
	tcpAlive,
	arpAlive,
}

var enrichers = []Enricher{
	portScan,
	macLookup,
}

func icmpAlive(ctx context.Context, addr netip.Addr, o Options) (Proof, bool) {
	if ok, _ := probe.PingAvailable(); !ok {
		return Proof{}, false
	}
	ok, rtt, err := probe.Ping(ctx, addr, o.Timeout)
	if err != nil || !ok {
		return Proof{}, false
	}
	return Proof{Method: "icmp", RTT: rtt}, true
}

// tcpAlive always runs: ARP cannot prove a host dead (point-to-point and VPN
// interfaces, this machine's own address, failed triggers). Hosts on a local
// subnet use the short LocalAlivePorts list and a capped timeout to keep
// socket pressure low: a LAN host answers in milliseconds, and dials to dead
// hosts would otherwise hold their sockets for the full timeout.
func tcpAlive(ctx context.Context, addr netip.Addr, o Options) (Proof, bool) {
	timeout := o.Timeout
	if target.IsLocal(addr, o.Locals) {
		timeout = min(timeout, localAliveTimeout)
	}
	ok, rtt := probe.TCPAlive(ctx, addr, alivePorts(addr, o), timeout)
	if !ok {
		return Proof{}, false
	}
	return Proof{Method: "tcp", RTT: rtt}, true
}

func alivePorts(addr netip.Addr, o Options) []int {
	if target.IsLocal(addr, o.Locals) {
		return probe.LocalAlivePorts
	}
	return probe.AlivePorts
}

func arpAlive(ctx context.Context, addr netip.Addr, o Options) (Proof, bool) {
	if !target.IsLocal(addr, o.Locals) {
		return Proof{}, false
	}
	start := time.Now()
	mac, ok := probe.ARP(ctx, addr, o.Timeout)
	if !ok {
		return Proof{}, false
	}
	return Proof{Method: "arp", RTT: time.Since(start), MAC: mac}, true
}

func macLookup(ctx context.Context, r *Result, o Options) {
	if r.MAC != "" || !target.IsLocal(r.IP, o.Locals) {
		return
	}
	// The host just answered, so the OS neighbor cache is warm.
	if mac, ok := probe.CachedMAC(r.IP); ok {
		r.MAC = mac
		return
	}
	if mac, ok := probe.ARP(ctx, r.IP, o.Timeout); ok {
		r.MAC = mac
	}
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
	return run(ctx, targets, o, aliveProbes, enrichers)
}

func run(ctx context.Context, targets []netip.Addr, o Options, probes []AliveProbe, enrichers []Enricher) <-chan Result {
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
				r := scanHost(ctx, addr, o, probes, enrichers)
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

func scanHost(ctx context.Context, addr netip.Addr, o Options, probes []AliveProbe, enrichers []Enricher) (r Result) {
	r = Result{IP: addr}
	if ctx.Err() != nil {
		return r
	}
	start := time.Now()
	var stage1 time.Duration
	if debug {
		defer func() {
			fmt.Fprintf(os.Stderr, "sonar-debug %s alive=%v by=%s stage1=%v total=%v ports=%v mac=%q\n",
				addr, r.Alive, r.AliveBy, stage1.Round(time.Millisecond),
				time.Since(start).Round(time.Millisecond), r.Ports, r.MAC)
		}()
	}

	// Stage 1: all alive probes in parallel, first success wins. Losers are
	// cancelled and not waited for: an uncancellable one would hold up stage
	// 2 for nothing. They can only send into the buffered proofs channel and
	// then exit, so nothing leaks past their own (bounded) runtime.
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	proofs := make(chan Proof, len(probes))
	var pwg sync.WaitGroup
	for _, p := range probes {
		pwg.Add(1)
		go func(p AliveProbe) {
			defer pwg.Done()
			if pr, ok := p(pctx, addr, o); ok {
				proofs <- pr
				cancel()
			}
		}(p)
	}
	allDone := make(chan struct{})
	go func() {
		pwg.Wait()
		close(allDone)
	}()

	accept := func(pr Proof) {
		if !r.Alive {
			r.Alive = true
			r.AliveBy = pr.Method
			r.RTT = pr.RTT
		}
		if r.MAC == "" {
			r.MAC = pr.MAC
		}
	}
	// drain takes proofs already delivered (e.g. a losing ARP probe's MAC)
	// without waiting for more.
	drain := func() {
		for {
			select {
			case pr := <-proofs:
				accept(pr)
			default:
				return
			}
		}
	}
	select {
	case pr := <-proofs:
		accept(pr)
		cancel()
	case <-allDone:
		// Every send happened before its pwg.Done, so none is in flight.
	}
	drain()
	stage1 = time.Since(start)
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
	drain()
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
