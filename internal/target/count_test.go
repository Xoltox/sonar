package target

import (
	"net/netip"
	"testing"
)

func TestCountHosts(t *testing.T) {
	locals := []Local{
		{Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{Prefix: netip.MustParsePrefix("192.168.1.0/25")},
		{Prefix: netip.MustParsePrefix("10.0.0.0/30")},
	}
	if got, want := CountHosts(locals), uint64(len(Hosts(locals))); got != want {
		t.Fatalf("got %d want %d", got, want)
	}
}
