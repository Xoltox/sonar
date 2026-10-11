package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var errMDNSMalformed = errors.New("mdns: malformed response")

// reverseName returns d.c.b.a.in-addr.arpa for an IPv4 address.
func reverseName(a netip.Addr) string {
	b := a.As4()
	return strconv.Itoa(int(b[3])) + "." + strconv.Itoa(int(b[2])) + "." +
		strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[0])) + ".in-addr.arpa"
}

// encodePTRQuery builds a single-question DNS PTR query. qu sets the mDNS
// unicast-response bit.
func encodePTRQuery(id uint16, name string, qu bool) []byte {
	b := make([]byte, 0, 18+len(name))
	b = binary.BigEndian.AppendUint16(b, id)
	b = append(b, 0, 0) // flags
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" || len(l) > 63 {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 12) // PTR
	class := uint16(1)
	if qu {
		class |= 0x8000
	}
	return binary.BigEndian.AppendUint16(b, class)
}

// readName decodes a possibly compressed name at off and returns it (no
// trailing dot) plus the offset just past the name at its original position.
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	jumps := 0
	for {
		if off < 0 || off >= len(b) {
			return "", 0, errMDNSMalformed
		}
		l := int(b[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return sb.String(), next, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return "", 0, errMDNSMalformed
			}
			if next < 0 {
				next = off + 2
			}
			jumps++
			if jumps > 16 {
				return "", 0, errMDNSMalformed
			}
			off = (l&0x3F)<<8 | int(b[off+1])
		case l&0xC0 != 0:
			return "", 0, errMDNSMalformed
		default:
			if off+1+l > len(b) {
				return "", 0, errMDNSMalformed
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(b[off+1 : off+1+l])
			if sb.Len() > 255 {
				return "", 0, errMDNSMalformed
			}
			off += 1 + l
		}
	}
}

// parsePTRAnswer returns the PTR target of the first answer whose owner name
// equals name (case-insensitive). The message ID is not checked.
func parsePTRAnswer(b []byte, name string) (string, error) {
	if len(b) < 12 {
		return "", errMDNSMalformed
	}
	if b[2]&0x80 == 0 {
		return "", errors.New("mdns: not a response")
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		if _, off, err = readName(b, off); err != nil {
			return "", err
		}
		off += 4
		if off > len(b) {
			return "", errMDNSMalformed
		}
	}
	want := strings.TrimSuffix(name, ".")
	for i := 0; i < an; i++ {
		var owner string
		if owner, off, err = readName(b, off); err != nil {
			return "", err
		}
		if off+10 > len(b) {
			return "", errMDNSMalformed
		}
		typ := binary.BigEndian.Uint16(b[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(b[off+8 : off+10]))
		off += 10
		if off+rdlen > len(b) {
			return "", errMDNSMalformed
		}
		if typ == 12 && strings.EqualFold(owner, want) {
			target, _, err := readName(b[:off+rdlen], off)
			if err != nil {
				return "", err
			}
			if target != "" {
				return target, nil
			}
		}
		off += rdlen
	}
	return "", errors.New("mdns: no matching answer")
}

// MDNSName asks the host for its .local name with a legacy-unicast PTR query,
// then a multicast QU query. It returns "" if nothing answers.
func MDNSName(ctx context.Context, addr netip.Addr, timeout time.Duration) string {
	if !addr.Is4() || timeout <= 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	release, err := acquire(ctx)
	if err != nil {
		return ""
	}
	defer release()

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return ""
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	rev := reverseName(addr)
	start := time.Now()
	phases := []struct {
		dst netip.AddrPort
		qu  bool
		end time.Time
	}{
		{netip.AddrPortFrom(addr, 5353), false, start.Add(timeout / 2)},
		{netip.AddrPortFrom(netip.AddrFrom4([4]byte{224, 0, 0, 251}), 5353), true, start.Add(timeout)},
	}
	buf := make([]byte, 4096)
	for _, ph := range phases {
		if _, err := conn.WriteToUDPAddrPort(encodePTRQuery(0, rev, ph.qu), ph.dst); err != nil {
			continue
		}
		conn.SetReadDeadline(ph.end)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				break
			}
			if from.Addr().Unmap() != addr {
				continue
			}
			if nm, perr := parsePTRAnswer(buf[:n], rev); perr == nil {
				return nm
			}
		}
		if ctx.Err() != nil {
			return ""
		}
	}
	return ""
}
