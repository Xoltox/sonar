package probe

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestEncodePTRQueryGolden(t *testing.T) {
	want := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		1, '4', 1, '3', 1, '2', 1, '1', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0,
		0x00, 0x0c, 0x00, 0x01,
	}
	if got := encodePTRQuery(0, "4.3.2.1.in-addr.arpa", false); !bytes.Equal(got, want) {
		t.Fatalf("got % x\nwant % x", got, want)
	}
	qu := encodePTRQuery(0x1234, "4.3.2.1.in-addr.arpa.", true)
	if qu[0] != 0x12 || qu[1] != 0x34 {
		t.Fatalf("id: % x", qu[:2])
	}
	if !bytes.HasSuffix(qu, []byte{0x00, 0x0c, 0x80, 0x01}) {
		t.Fatalf("QU tail: % x", qu[len(qu)-4:])
	}
}

func TestReverseName(t *testing.T) {
	if got := reverseName(netip.MustParseAddr("192.168.0.100")); got != "100.0.168.192.in-addr.arpa" {
		t.Fatal(got)
	}
}

func TestParsePTRAnswer(t *testing.T) {
	b := []byte{0, 0, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}
	b = append(b, encodePTRQuery(0, "4.3.2.1.in-addr.arpa", false)[12:]...)
	b = append(b, 0xC0, 0x0C, 0, 12, 0x80, 1, 0, 0, 0, 120)
	rd := []byte{6, 'O', 'c', 't', 'o', 'p', 'i', 5, 'l', 'o', 'c', 'a', 'l', 0}
	b = append(b, 0, byte(len(rd)))
	b = append(b, rd...)

	got, err := parsePTRAnswer(b, "4.3.2.1.IN-ADDR.arpa")
	if err != nil || got != "Octopi.local" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parsePTRAnswer(b, "5.3.2.1.in-addr.arpa"); err == nil {
		t.Fatal("expected owner mismatch error")
	}
	for i := 0; i < len(b); i++ {
		if _, err := parsePTRAnswer(b[:i], "4.3.2.1.in-addr.arpa"); err == nil {
			t.Fatalf("prefix %d: expected error", i)
		}
	}

	// rdata with a compression pointer back into the question name.
	c := []byte{0, 0, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}
	c = append(c, encodePTRQuery(0, "4.3.2.1.in-addr.arpa", false)[12:]...)
	c = append(c, 0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 120, 0, 7, 4, 'h', 'o', 's', 't', 0xC0, 0x14)
	// offset 20 is the "in-addr" label of the question name.
	if got, err := parsePTRAnswer(c, "4.3.2.1.in-addr.arpa"); err != nil || got != "host.in-addr.arpa" {
		t.Fatalf("pointer rdata: %q, %v", got, err)
	}
	for i := 0; i < len(c); i++ {
		if _, err := parsePTRAnswer(c[:i], "4.3.2.1.in-addr.arpa"); err == nil {
			t.Fatalf("c prefix %d: expected error", i)
		}
	}
}

func TestParsePTRAnswerPointerLoop(t *testing.T) {
	b := []byte{0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}
	b = append(b, 0xC0, 0x0C) // owner points at itself
	b = append(b, 0, 12, 0, 1, 0, 0, 0, 1, 0, 0)
	if _, err := parsePTRAnswer(b, "x"); err == nil {
		t.Fatal("expected loop error")
	}
	// rdata pointer loop
	c := []byte{0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0}
	c = append(c, 0, 12, 0, 1, 0, 0, 0, 1, 0, 2)
	c = append(c, 0xC0, byte(len(c)))
	if _, err := parsePTRAnswer(c, ""); err == nil {
		t.Fatal("expected rdata loop error")
	}
}

func TestParsePTRAnswerGarbage(t *testing.T) {
	for i := 0; i < 2000; i++ {
		b := make([]byte, i%80)
		for j := range b {
			b[j] = byte(i*31 + j*17)
		}
		if len(b) > 3 {
			b[2] |= 0x80
		}
		parsePTRAnswer(b, "4.3.2.1.in-addr.arpa")
	}
}

func TestMDNSNameLoopback(t *testing.T) {
	start := time.Now()
	got := MDNSName(context.Background(), netip.MustParseAddr("127.0.0.1"), 500*time.Millisecond)
	el := time.Since(start)
	t.Logf("MDNSName(127.0.0.1) = %q in %v", got, el)
	if el > 2*time.Second {
		t.Fatalf("too slow: %v", el)
	}
}

func TestLiveHTTPMDNS(t *testing.T) {
	if os.Getenv("SONAR_LIVE") != "1" {
		t.Skip("SONAR_LIVE not set")
	}
	for _, s := range []string{"192.168.0.1", "192.168.0.100"} {
		a := netip.MustParseAddr(s)
		t.Logf("%s title=%q mdns=%q", s,
			HTTPTitle(context.Background(), a, 800*time.Millisecond),
			MDNSName(context.Background(), a, time.Second))
	}
}
