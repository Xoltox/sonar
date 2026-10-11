package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
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
