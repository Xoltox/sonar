package probe

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestEncodeNBSTATQuery(t *testing.T) {
	want := []byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'}
	for i := 0; i < 15; i++ {
		want = append(want, 'A', 'A')
	}
	want = append(want, 0x00, 0x00, 0x21, 0x00, 0x01)
	if len(want) != 50 {
		t.Fatalf("bad expectation len %d", len(want))
	}
	if got := encodeNBSTATQuery(0x1234); !bytes.Equal(got, want) {
		t.Fatalf("got % x\nwant % x", got, want)
	}
}

func nbEntry(name string, suffix byte, flags uint16) []byte {
	e := make([]byte, 18)
	for i := range e[:15] {
		e[i] = ' '
	}
	copy(e, name)
	e[15] = suffix
	e[16], e[17] = byte(flags>>8), byte(flags)
	return e
}

func validNBResponse(txid uint16, compressed bool) []byte {
	b := []byte{byte(txid >> 8), byte(txid), 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	if compressed {
		b = append(b, 0xC0, 0x0C)
	} else {
		b = append(b, 0x20, 'C', 'K')
		for i := 0; i < 15; i++ {
			b = append(b, 'A', 'A')
		}
		b = append(b, 0)
	}
	b = append(b, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0)
	rdata := []byte{3}
	rdata = append(rdata, nbEntry("WORKGROUP", 0x00, 0x8400)...)
	rdata = append(rdata, nbEntry("DESKTOP-PARTH", 0x00, 0x0400)...)
	rdata = append(rdata, nbEntry("DESKTOP-PARTH", 0x20, 0x0400)...)
	rdata = append(rdata, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
	rdata = append(rdata, make([]byte, 40)...)
	b = append(b, byte(len(rdata)>>8), byte(len(rdata)))
	return append(b, rdata...)
}

func TestParseNBSTATResponse(t *testing.T) {
	for _, comp := range []bool{false, true} {
		name, mac, err := parseNBSTATResponse(validNBResponse(0xBEEF, comp), 0xBEEF)
		if err != nil || name != "DESKTOP-PARTH" || mac != "11:22:33:44:55:66" {
			t.Fatalf("comp=%v got %q %q %v", comp, name, mac, err)
		}
	}
	if _, _, err := parseNBSTATResponse(validNBResponse(1, false), 2); err == nil {
		t.Fatal("txid mismatch accepted")
	}
}

func TestParseNBSTATRDLengthBoundsMAC(t *testing.T) {
	b := validNBResponse(9, false)
	// RDLENGTH sits 10 bytes before NUM_NAMES, which is at 12+34+10.
	rdlOff := 12 + 34 + 8
	// Declare rdata ending 3 bytes into the statistics block.
	rdl := 1 + 18*3 + 3
	b[rdlOff], b[rdlOff+1] = byte(rdl>>8), byte(rdl)
	name, mac, err := parseNBSTATResponse(b, 9)
	if err != nil || name != "DESKTOP-PARTH" || mac != "" {
		t.Fatalf("got %q %q %v, want name with empty mac", name, mac, err)
	}
	// RDLENGTH too small to hold the declared names is malformed.
	rdl = 1 + 18
	b[rdlOff], b[rdlOff+1] = byte(rdl>>8), byte(rdl)
	if _, _, err := parseNBSTATResponse(b, 9); err == nil {
		t.Fatal("names past RDLENGTH accepted")
	}
}

func TestParseNBSTATMalformed(t *testing.T) {
	full := validNBResponse(7, false)
	// header 12 + name 34 + fixed 11 + 3 entries = 111 bytes before the stats block.
	for i := 0; i < len(full); i++ {
		_, _, err := parseNBSTATResponse(full[:i], 7)
		if i < 12+34+11+18*3 && err == nil {
			t.Fatalf("prefix %d accepted", i)
		}
	}
	garbage := bytes.Repeat([]byte{0xFF}, 100)
	garbage[0], garbage[1] = 0, 7
	if _, _, err := parseNBSTATResponse(garbage, 7); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestNetBIOSNameLoopback(t *testing.T) {
	start := time.Now()
	n, m := NetBIOSName(context.Background(), netip.MustParseAddr("127.0.0.1"), 500*time.Millisecond)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("took %v", d)
	}
	t.Logf("name=%q mac=%q", n, m)
}
