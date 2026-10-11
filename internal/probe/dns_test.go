package probe

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestReverseDNSLoopback(t *testing.T) {
	start := time.Now()
	got := ReverseDNS(context.Background(), netip.MustParseAddr("127.0.0.1"), 500*time.Millisecond)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	t.Logf("127.0.0.1 -> %q", got)
}

func TestReverseDNSTimeout(t *testing.T) {
	start := time.Now()
	got := ReverseDNS(context.Background(), netip.MustParseAddr("192.0.2.1"), 300*time.Millisecond)
	if got != "" {
		t.Fatalf("got %q", got)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestReverseDNSNetBIOSLive(t *testing.T) {
	if os.Getenv("SONAR_LIVE") != "1" {
		t.Skip("set SONAR_LIVE=1")
	}
	for _, s := range []string{"192.168.0.1", "192.168.0.106"} {
		a := netip.MustParseAddr(s)
		n, m := NetBIOSName(context.Background(), a, 1500*time.Millisecond)
		t.Logf("%s dns=%q netbios=%q mac=%q", s, ReverseDNS(context.Background(), a, 1500*time.Millisecond), n, m)
	}
}
