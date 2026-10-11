package scan

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/target"
)

func TestRunLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := netip.MustParseAddr("127.0.0.1")
	var got []Result
	for r := range Run(ctx, []netip.Addr{addr}, Options{
		Timeout:     time.Second,
		Concurrency: 4,
		Ports:       []int{port},
	}) {
		got = append(got, r)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	r := got[0]
	if !r.Alive {
		t.Fatalf("127.0.0.1 not alive: %+v", r)
	}
	found := false
	for _, p := range r.Ports {
		if p == port {
			found = true
		}
	}
	if !found {
		t.Fatalf("port %d not in %v", port, r.Ports)
	}
}

func fakeProbe(delay time.Duration, p Proof, ok bool) AliveProbe {
	return func(ctx context.Context, addr netip.Addr, o Options) (Proof, bool) {
		select {
		case <-time.After(delay):
			return p, ok
		case <-ctx.Done():
			return Proof{}, false
		}
	}
}

func TestStage1FastProbeWins(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	probes := []AliveProbe{
		fakeProbe(2*time.Second, Proof{}, false),
		fakeProbe(10*time.Millisecond, Proof{Method: "arp", RTT: time.Millisecond, MAC: "aa:bb:cc:dd:ee:ff"}, true),
	}
	enriched := false
	enr := []Enricher{func(ctx context.Context, r *Result, o Options) { enriched = true }}
	start := time.Now()
	var got []Result
	for r := range run(context.Background(), []netip.Addr{addr}, Options{}, probes, enr) {
		got = append(got, r)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results", len(got))
	}
	r := got[0]
	if !r.Alive || r.AliveBy != "arp" || r.MAC != "aa:bb:cc:dd:ee:ff" || r.RTT != time.Millisecond {
		t.Fatalf("unexpected result: %+v", r)
	}
	if !enriched {
		t.Fatal("enricher not called")
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow probe was not cancelled")
	}
}

func TestStage1AllDead(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.2")
	probes := []AliveProbe{
		fakeProbe(time.Millisecond, Proof{}, false),
		fakeProbe(time.Millisecond, Proof{}, false),
	}
	enriched := false
	enr := []Enricher{func(ctx context.Context, r *Result, o Options) { enriched = true }}
	var got []Result
	for r := range run(context.Background(), []netip.Addr{addr}, Options{}, probes, enr) {
		got = append(got, r)
	}
	if len(got) != 1 || got[0].Alive {
		t.Fatalf("expected one dead result, got %+v", got)
	}
	if enriched {
		t.Fatal("enricher called for dead host")
	}
}

func TestRunCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	targets := make([]netip.Addr, 50)
	for i := range targets {
		targets[i] = netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})
	}
	probes := []AliveProbe{fakeProbe(time.Minute, Proof{}, false)}
	ch := run(ctx, targets, Options{Concurrency: 4}, probes, nil)
	time.AfterFunc(50*time.Millisecond, cancel)
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("channel did not close after cancel")
	}
}

// stubbornProbe ignores ctx, like an uncancellable OS call.
func stubbornProbe(delay time.Duration, p Proof, ok bool) AliveProbe {
	return func(ctx context.Context, addr netip.Addr, o Options) (Proof, bool) {
		time.Sleep(delay)
		return p, ok
	}
}

func TestStage1LoserNotAwaited(t *testing.T) {
	probes := []AliveProbe{
		stubbornProbe(1500*time.Millisecond, Proof{}, false),
		fakeProbe(10*time.Millisecond, Proof{Method: "icmp", RTT: time.Millisecond}, true),
	}
	start := time.Now()
	var got []Result
	for r := range run(context.Background(), []netip.Addr{netip.MustParseAddr("10.0.0.3")}, Options{}, probes, nil) {
		got = append(got, r)
	}
	if len(got) != 1 || !got[0].Alive || got[0].AliveBy != "icmp" {
		t.Fatalf("unexpected results: %+v", got)
	}
	if d := time.Since(start); d > 700*time.Millisecond {
		t.Fatalf("winner waited for an uncancellable loser: %v", d)
	}
}

func TestStage1LoserMACKept(t *testing.T) {
	probes := []AliveProbe{
		fakeProbe(5*time.Millisecond, Proof{Method: "icmp", RTT: time.Millisecond}, true),
		stubbornProbe(50*time.Millisecond, Proof{Method: "arp", MAC: "AA:BB:CC:DD:EE:FF"}, true),
	}
	enr := []Enricher{func(ctx context.Context, r *Result, o Options) { time.Sleep(200 * time.Millisecond) }}
	var got []Result
	for r := range run(context.Background(), []netip.Addr{netip.MustParseAddr("10.0.0.4")}, Options{}, probes, enr) {
		got = append(got, r)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results", len(got))
	}
	r := got[0]
	if r.AliveBy != "icmp" || r.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("want icmp winner with loser's MAC, got %+v", r)
	}
}

func TestStage1EnricherMACWinsOverLateLoser(t *testing.T) {
	probes := []AliveProbe{
		fakeProbe(time.Millisecond, Proof{Method: "icmp"}, true),
		stubbornProbe(100*time.Millisecond, Proof{Method: "arp", MAC: "11:11:11:11:11:11"}, true),
	}
	enr := []Enricher{func(ctx context.Context, r *Result, o Options) {
		time.Sleep(200 * time.Millisecond)
		r.MAC = "22:22:22:22:22:22"
	}}
	for r := range run(context.Background(), []netip.Addr{netip.MustParseAddr("10.0.0.5")}, Options{}, probes, enr) {
		if r.MAC != "22:22:22:22:22:22" {
			t.Fatalf("enricher MAC overwritten: %+v", r)
		}
	}
}

func TestStage1NoGoroutineLeak(t *testing.T) {
	base := runtime.NumGoroutine()
	probes := []AliveProbe{
		stubbornProbe(200*time.Millisecond, Proof{}, false),
		fakeProbe(time.Millisecond, Proof{Method: "tcp"}, true),
	}
	targets := make([]netip.Addr, 20)
	for i := range targets {
		targets[i] = netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})
	}
	for range run(context.Background(), targets, Options{Concurrency: 8}, probes, nil) {
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > base {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines: %d, baseline %d", runtime.NumGoroutine(), base)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestAlivePorts(t *testing.T) {
	o := Options{Locals: []target.Local{{
		Iface:  "eth0",
		Addr:   netip.MustParseAddr("192.168.50.10"),
		Prefix: netip.MustParsePrefix("192.168.50.0/24"),
	}}}
	if got := alivePorts(netip.MustParseAddr("192.168.50.20"), o); !slices.Equal(got, probe.LocalAlivePorts) {
		t.Errorf("local host ports = %v, want %v", got, probe.LocalAlivePorts)
	}
	if got := alivePorts(netip.MustParseAddr("10.9.9.9"), o); !slices.Equal(got, probe.AlivePorts) {
		t.Errorf("remote host ports = %v, want %v", got, probe.AlivePorts)
	}
}
