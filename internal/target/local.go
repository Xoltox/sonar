package target

import (
	"net"
	"net/netip"
	"strings"
)

// Local is one IPv4 interface subnet on this machine.
type Local struct {
	Iface  string
	Addr   netip.Addr   // this machine's address on the interface
	Prefix netip.Prefix // masked subnet to scan
}

var linkLocal = netip.MustParsePrefix("169.254.0.0/16")

var (
	virtualContains = []string{
		"vethernet", "wsl", "hyper-v", "virtualbox", "vmware", "vmnet", "docker",
		"virbr", "vboxnet", "tailscale", "npcap loopback", "awdl",
	}
	virtualPrefixes = []string{
		"br-", "veth", "utun", "tun", "tap", "zt", "wg", "bridge", "llw", "anpi", "ap1",
	}
)

// isVirtual reports whether an interface looks like a virtual adapter
// (VM host-only, container bridge, VPN tunnel) rather than a real LAN. Only the name is used: a MAC OUI test would drop
// the real NIC when running inside a VM guest.
func isVirtual(name string) bool {
	n := strings.ToLower(name)
	for _, s := range virtualContains {
		if strings.Contains(n, s) {
			return true
		}
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// LocalSubnets returns the up, non-loopback, non-virtual IPv4 interface
// subnets. If filtering removes everything it falls back to LocalSubnetsAll.
func LocalSubnets() ([]Local, error) {
	out, err := localSubnets(true)
	if err != nil || len(out) > 0 {
		return out, err
	}
	return localSubnets(false)
}

// LocalSubnetsAll returns every up, non-loopback IPv4 interface subnet,
// including virtual adapters.
// Link-local and /32 addresses are skipped, and prefixes shorter than /16
// are narrowed to the /24 containing the address.
func LocalSubnetsAll() ([]Local, error) {
	return localSubnets(false)
}

func localSubnets(skipVirtual bool) ([]Local, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Local
	seen := map[netip.Prefix]bool{}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if skipVirtual && isVirtual(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if !addr.Is4() || linkLocal.Contains(addr) {
				continue
			}
			ones, bits := ipn.Mask.Size()
			if bits != 32 || ones >= 32 {
				continue
			}
			if ones < 16 {
				ones = 24
			}
			p := netip.PrefixFrom(addr, ones).Masked()
			if seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, Local{Iface: ifc.Name, Addr: addr, Prefix: p})
		}
	}
	return out, nil
}

// IsLocal reports whether addr falls inside any of the locals' prefixes.
func IsLocal(addr netip.Addr, locals []Local) bool {
	for _, l := range locals {
		if l.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Hosts expands locals into a deduped sorted host list.
func Hosts(locals []Local) []netip.Addr {
	spans := make([]span, 0, len(locals))
	for _, l := range locals {
		spans = append(spans, prefixSpan(l.Prefix))
	}
	return expandSpans(mergeSpans(spans))
}
