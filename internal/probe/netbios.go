package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// encodeNBSTATQuery builds a 50-byte NetBIOS node status request for "*".
func encodeNBSTATQuery(txid uint16) []byte {
	b := make([]byte, 0, 50)
	b = binary.BigEndian.AppendUint16(b, txid)
	b = append(b, 0, 0) // flags
	b = binary.BigEndian.AppendUint16(b, 1)
	b = append(b, 0, 0, 0, 0, 0, 0)
	b = append(b, 0x20)
	b = append(b, 'C', 'K')
	for i := 0; i < 15; i++ {
		b = append(b, 'A', 'A')
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0x0021)
	b = binary.BigEndian.AppendUint16(b, 0x0001)
	return b
}

var errNBMalformed = errors.New("netbios: malformed response")

// skipName returns the offset just past the DNS-style name at off.
func skipName(b []byte, off int) (int, error) {
	for steps := 0; steps < 64; steps++ {
		if off >= len(b) {
			return 0, errNBMalformed
		}
		l := int(b[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(b) {
				return 0, errNBMalformed
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, errNBMalformed
		}
		off += 1 + l
	}
	return 0, errNBMalformed
}

func cleanNBName(raw []byte) (string, bool) {
	s := strings.TrimRight(string(raw), " \x00")
	if s == "" {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return "", false
		}
	}
	return s, true
}

// parseNBSTATResponse extracts the workstation name and unit ID MAC.
func parseNBSTATResponse(b []byte, txid uint16) (name, mac string, err error) {
	if len(b) < 12 {
		return "", "", errNBMalformed
	}
	if binary.BigEndian.Uint16(b[0:2]) != txid {
		return "", "", errors.New("netbios: txid mismatch")
	}
	if b[2]&0x80 == 0 {
		return "", "", errors.New("netbios: not a response")
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	if an < 1 {
		return "", "", errors.New("netbios: no answer")
	}
	off := 12
	for i := 0; i < qd; i++ {
		off, err = skipName(b, off)
		if err != nil {
			return "", "", err
		}
		off += 4
	}
	off, err = skipName(b, off)
	if err != nil {
		return "", "", err
	}
	// TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) NUM_NAMES(1)
	if off+11 > len(b) {
		return "", "", errNBMalformed
	}
	if binary.BigEndian.Uint16(b[off:off+2]) != 0x0021 {
		return "", "", errors.New("netbios: not NBSTAT")
	}
	rdEnd := off + 10 + int(binary.BigEndian.Uint16(b[off+8:off+10]))
	if rdEnd > len(b) {
		rdEnd = len(b)
	}
	if off+11 > rdEnd {
		return "", "", errNBMalformed
	}
	n := int(b[off+10])
	off += 11
	if off+n*18 > rdEnd {
		return "", "", errNBMalformed
	}
	var fallback string
	for i := 0; i < n; i++ {
		e := b[off+i*18 : off+i*18+18]
		flags := binary.BigEndian.Uint16(e[16:18])
		if flags&0x8000 != 0 {
			continue
		}
		s, ok := cleanNBName(e[:15])
		if !ok {
			continue
		}
		switch e[15] {
		case 0x00:
			if name == "" {
				name = s
			}
		case 0x20:
			if fallback == "" {
				fallback = s
			}
		}
	}
	if name == "" {
		name = fallback
	}
	if name == "" {
		return "", "", errors.New("netbios: no workstation name")
	}
	off += n * 18
	if off+6 <= rdEnd {
		m := b[off : off+6]
		if m[0]|m[1]|m[2]|m[3]|m[4]|m[5] != 0 {
			mac = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
		}
	}
	return name, mac, nil
}

// NetBIOSName sends an NBSTAT node status query (UDP 137) and returns the
// host's unique workstation name, and the unit ID MAC ("" if zero).
func NetBIOSName(ctx context.Context, addr netip.Addr, timeout time.Duration) (name, mac string) {
	if !addr.Is4() {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	release, err := acquire(ctx)
	if err != nil {
		return "", ""
	}
	defer release()

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", ""
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	var r [2]byte
	if _, err := rand.Read(r[:]); err != nil {
		return "", ""
	}
	txid := binary.BigEndian.Uint16(r[:])
	dst := net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, 137))
	if _, err := conn.WriteToUDP(encodeNBSTATQuery(txid), dst); err != nil {
		return "", ""
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return "", ""
		}
		if from.Addr().Unmap() != addr {
			continue
		}
		if nm, m, perr := parseNBSTATResponse(buf[:n], txid); perr == nil {
			return nm, m
		}
	}
}
