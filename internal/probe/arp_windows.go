//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procSendARP        = iphlpapi.NewProc("SendARP")
	procGetIpNetTable2 = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = iphlpapi.NewProc("FreeMibTable")
)

// MIB_IPNET_TABLE2 / MIB_IPNET_ROW2 layout (same on 386, amd64 and arm64).
const (
	ipnetTableRows   = 8 // NumEntries ULONG, then rows aligned to 8
	ipnetRowSize     = 88
	ipnetRowPhys     = 40 // PhysicalAddress[32]
	ipnetRowPhysLen  = 72 // PhysicalAddressLength ULONG
	ipnetRowState    = 76 // NL_NEIGHBOR_STATE
	nlnsProbe        = 2
	nlnsReachable    = 5
	nlnsPermanent    = 6
	sockaddrInFamily = 0 // SOCKADDR_INET.Ipv4.sin_family
	sockaddrInAddr   = 4 // SOCKADDR_INET.Ipv4.sin_addr
)

var neighborTable = &macTable{load: loadIPNetTable}

// loadIPNetTable reads the IPv4 neighbor cache via GetIpNetTable2. It is a
// local read and sends no traffic.
func loadIPNetTable() map[netip.Addr]neighbor {
	out := make(map[netip.Addr]neighbor)
	if procGetIpNetTable2.Find() != nil || procFreeMibTable.Find() != nil {
		return out
	}
	var table *byte
	r, _, _ := procGetIpNetTable2.Call(uintptr(windows.AF_INET), uintptr(unsafe.Pointer(&table)))
	if r != 0 || table == nil {
		return out
	}
	defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	n := *(*uint32)(unsafe.Pointer(table))
	rows := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(table), ipnetTableRows)), int(n)*ipnetRowSize)
	for i := 0; i < int(n); i++ {
		row := rows[i*ipnetRowSize : (i+1)*ipnetRowSize]
		if binary.NativeEndian.Uint16(row[sockaddrInFamily:]) != windows.AF_INET {
			continue
		}
		state := binary.NativeEndian.Uint32(row[ipnetRowState:])
		if state < nlnsProbe || state > nlnsPermanent {
			continue // unreachable or incomplete: no MAC
		}
		if binary.NativeEndian.Uint32(row[ipnetRowPhysLen:]) != 6 {
			continue
		}
		phys := row[ipnetRowPhys : ipnetRowPhys+6]
		mac := usableMAC(phys)
		if mac == "" {
			continue
		}
		var a4 [4]byte
		copy(a4[:], row[sockaddrInAddr:sockaddrInAddr+4])
		out[netip.AddrFrom4(a4)] = neighbor{mac: mac, confirmed: state == nlnsReachable}
	}
	return out
}

type arpResult struct {
	mac string
	ok  bool
}

func arpResolve(ctx context.Context, addr netip.Addr, timeout time.Duration) (string, bool) {
	// A Reachable cache entry is a fresh ARP reply: no need to park a thread.
	if mac, ok := neighborTable.confirmed(addr); ok {
		return mac, true
	}
	release, err := acquireARP(ctx)
	if err != nil {
		return "", false
	}
	// SendARP blocks its thread (about 3s for a dead host) and cannot be
	// cancelled, so it runs in its own goroutine that owns the slot until it
	// returns. The slot is not a socket slot, so dials are never starved.
	ch := make(chan arpResult, 1)
	go func() {
		defer release()
		mac, ok := sendARP(addr)
		ch <- arpResult{mac, ok}
	}()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r.mac, r.ok
	case <-t.C:
	case <-ctx.Done():
	}
	return "", false
}

func sendARP(addr netip.Addr) (string, bool) {
	if err := procSendARP.Find(); err != nil {
		return "", false
	}
	a4 := addr.As4()
	// DestIP is the address bytes as they sit in memory (network order).
	dest := binary.NativeEndian.Uint32(a4[:])
	var buf [2]uint32
	n := uint32(6)
	r, _, _ := procSendARP.Call(uintptr(dest), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)))
	if r != 0 || n < 6 {
		return "", false
	}
	b := (*[8]byte)(unsafe.Pointer(&buf[0]))[:6:6]
	mac := normalizeMAC(formatMAC(b))
	return mac, mac != ""
}
