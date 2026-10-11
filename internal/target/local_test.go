package target

import "testing"

func TestIsVirtual(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"Ethernet", false},
		{"Wi-Fi", false},
		{"eth0", false},
		{"wlan0", false},
		{"en0", false},
		{"enp3s0", false},
		{"wlp2s0", false},
		{"vEthernet (WSL)", true},
		{"vEthernet (Default Switch)", true},
		{"docker0", true},
		{"br-1a2b3c", true},
		{"veth12ab", true},
		{"virbr0", true},
		{"utun3", true},
		{"tailscale0", true},
		{"wg0", true},
		{"bridge100", true},
		{"VirtualBox Host-Only Network", true},
		{"Ethernet 3", false},
		{"eth1", false},
	}
	for _, tc := range tests {
		if got := isVirtual(tc.name); got != tc.want {
			t.Errorf("isVirtual(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
