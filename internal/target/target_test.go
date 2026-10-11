package target

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		spec        string
		count       int
		first, last string
	}{
		{"cidr24", "192.168.1.0/24", 254, "192.168.1.1", "192.168.1.254"},
		{"cidr31", "10.0.0.4/31", 2, "10.0.0.4", "10.0.0.5"},
		{"cidr32", "10.0.0.9/32", 1, "10.0.0.9", "10.0.0.9"},
		{"cidr30", "10.0.0.0/30", 2, "10.0.0.1", "10.0.0.2"},
		{"range across octets", "10.0.0.250-10.0.1.5", 12, "10.0.0.250", "10.0.1.5"},
		{"short range", "10.0.0.1-50", 50, "10.0.0.1", "10.0.0.50"},
		{"single", "10.1.2.3", 1, "10.1.2.3", "10.1.2.3"},
		{"comma with dups", "10.0.0.1, 10.0.0.1-3 ,10.0.0.2", 3, "10.0.0.1", "10.0.0.3"},
		{"unsorted list", "10.0.0.9,10.0.0.1", 2, "10.0.0.1", "10.0.0.9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.count {
				t.Fatalf("count = %d, want %d", len(got), tc.count)
			}
			if got[0].String() != tc.first || got[len(got)-1].String() != tc.last {
				t.Fatalf("first/last = %s/%s, want %s/%s", got[0], got[len(got)-1], tc.first, tc.last)
			}
			for i := 1; i < len(got); i++ {
				if !got[i-1].Less(got[i]) {
					t.Fatalf("not strictly ascending at %d", i)
				}
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct{ name, spec, token string }{
		{"bad octet", "10.0.0.300", "10.0.0.300"},
		{"reversed range", "10.0.0.50-10.0.0.1", "10.0.0.50-10.0.0.1"},
		{"reversed short", "10.0.0.50-1", "10.0.0.50-1"},
		{"ipv6", "fe80::1", "fe80::1"},
		{"ipv6 cidr", "2001:db8::/32", "2001:db8::/32"},
		{"empty", "", "empty"},
		{"empty item", "10.0.0.1,,10.0.0.2", "empty"},
		{"bad cidr", "10.0.0.0/33", "10.0.0.0/33"},
		{"bad short end", "10.0.0.1-300", "10.0.0.1-300"},
		{"garbage", "hello", "hello"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.spec)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.token) {
				t.Fatalf("error %q does not mention %q", err, tc.token)
			}
		})
	}
}

func TestParseAll(t *testing.T) {
	got, err := ParseAll([]string{"10.0.0.1-5", "10.0.0.3-8"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("count = %d, want 8", len(got))
	}

	if _, err := ParseAll([]string{"10.0.0.0/15"}, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want --force error, got %v", err)
	}
	if _, err := ParseAll([]string{"10.0.0.0/8"}, false); err == nil {
		t.Fatal("want error for /8 without force")
	}
	got, err = ParseAll([]string{"10.0.0.0/15"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 131070 {
		t.Fatalf("count = %d, want 131070", len(got))
	}
	if _, err := ParseAll([]string{"10.0.0.1", "bogus"}, false); err == nil {
		t.Fatal("want error for bogus arg")
	}
}

func TestIsLocalAndHosts(t *testing.T) {
	locals := []Local{
		{Iface: "a", Addr: netip.MustParseAddr("192.168.1.5"), Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		{Iface: "b", Addr: netip.MustParseAddr("10.0.0.2"), Prefix: netip.MustParsePrefix("10.0.0.0/30")},
	}
	if !IsLocal(netip.MustParseAddr("192.168.1.99"), locals) {
		t.Error("192.168.1.99 should be local")
	}
	if IsLocal(netip.MustParseAddr("192.168.2.1"), locals) {
		t.Error("192.168.2.1 should not be local")
	}
	if IsLocal(netip.MustParseAddr("1.1.1.1"), nil) {
		t.Error("nothing is local with no locals")
	}
	hosts := Hosts(locals)
	if len(hosts) != 256 {
		t.Fatalf("hosts = %d, want 256", len(hosts))
	}
	if hosts[0].String() != "10.0.0.1" {
		t.Errorf("first host = %s", hosts[0])
	}
}

func TestLocalSubnets(t *testing.T) {
	locals, err := LocalSubnets()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range locals {
		t.Logf("%s %s %s", l.Iface, l.Addr, l.Prefix)
	}
}
