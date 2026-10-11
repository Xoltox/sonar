package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPingLoopback(t *testing.T) {
	ok, rtt, err := Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 2*time.Second)
	if err != nil {
		t.Skip("icmp unavailable: " + err.Error())
	}
	if !ok {
		t.Fatal("expected reply from 127.0.0.1")
	}
	t.Logf("rtt=%v", rtt)
}

func TestPingUnroutable(t *testing.T) {
	start := time.Now()
	ok, _, err := Ping(context.Background(), netip.MustParseAddr("192.0.2.1"), 300*time.Millisecond)
	if err != nil {
		t.Skip("icmp unavailable: " + err.Error())
	}
	if ok {
		t.Fatal("unexpected reply from TEST-NET")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took too long: %v", d)
	}
}

func TestPingAvailable(t *testing.T) {
	ok, hint := PingAvailable()
	t.Logf("available=%v hint=%q", ok, hint)
}
