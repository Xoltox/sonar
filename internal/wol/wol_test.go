package wol

import (
	"bytes"
	"testing"
)

func TestPacket(t *testing.T) {
	for _, mac := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"} {
		p, err := Packet(mac)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 102 {
			t.Fatalf("len %d", len(p))
		}
		if !bytes.Equal(p[:6], bytes.Repeat([]byte{0xFF}, 6)) {
			t.Fatal("bad header")
		}
		want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
		for i := 0; i < 16; i++ {
			if !bytes.Equal(p[6+6*i:12+6*i], want) {
				t.Fatalf("repetition %d wrong", i)
			}
		}
	}
}

func TestPacketBad(t *testing.T) {
	for _, mac := range []string{"", "AA:BB", "ZZ:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF:00:11"} {
		if _, err := Packet(mac); err == nil {
			t.Errorf("Packet(%q): want error", mac)
		}
	}
	if err := Send("bad"); err == nil {
		t.Error("Send(bad): want error")
	}
}
