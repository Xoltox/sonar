// Package wol sends Wake-on-LAN magic packets.
package wol

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Packet builds the 102-byte magic packet for mac (":" or "-" separated).
func Packet(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) != 6 {
		return nil, fmt.Errorf("invalid MAC address %q", mac)
	}
	p := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		p = append(p, 0xFF)
	}
	for i := 0; i < 16; i++ {
		p = append(p, hw...)
	}
	return p, nil
}

// Send broadcasts the magic packet to 255.255.255.255:9 and to the directed
// broadcast of every up, non-loopback IPv4 interface. It succeeds if at least
// one send worked.
func Send(mac string) error {
	pkt, err := Packet(mac)
	if err != nil {
		return err
	}
	dests := []netip.Addr{netip.AddrFrom4([4]byte{255, 255, 255, 255})}
	dests = append(dests, directedBroadcasts()...)
	var ok bool
	var last error
	for _, d := range dests {
		conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(d, 9)))
		if err != nil {
			last = err
			continue
		}
		_, err = conn.Write(pkt)
		conn.Close()
		if err != nil {
			last = err
			continue
		}
		ok = true
	}
	if !ok {
		if last == nil {
			last = errors.New("no destination")
		}
		return fmt.Errorf("send magic packet: %w", last)
	}
	return nil
}

func directedBroadcasts() []netip.Addr {
	var out []netip.Addr
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
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
			ip := ipn.IP.To4()
			if ip == nil || len(ipn.Mask) != 4 && len(ipn.Mask) != 16 {
				continue
			}
			m := ipn.Mask
			if len(m) == 16 {
				m = m[12:]
			}
			var b [4]byte
			for i := range b {
				b[i] = ip[i] | ^m[i]
			}
			out = append(out, netip.AddrFrom4(b))
		}
	}
	return out
}
