//go:build windows

package probe

import (
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// sioTCPInitialRTO is SIO_TCP_INITIAL_RTO, _WSAIOW(IOC_VENDOR, 17).
	sioTCPInitialRTO = 0x98000011
	// tcpInitialRTONoSYNRetransmissions is TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS.
	tcpInitialRTONoSYNRetransmissions = 0xFE
)

// dialControl turns off SYN retransmission on the socket. Windows answers a
// RST to its SYN by retrying the SYN twice, so a closed port on a remote
// host reports "refused" only after about 2s, far past the probe timeout;
// with no SYN retransmissions it reports it in one round trip. The initial
// RTO is set to the time left so the single SYN waits for the whole
// timeout; dialPort's staggered attempts replace the lost retransmits.
// Failure (pre-Windows 8) is ignored and leaves the OS default.
func dialControl(deadline time.Time) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		ms := time.Until(deadline).Milliseconds()
		if ms < 1 {
			ms = 1
		}
		if ms > 0xFFFF {
			ms = 0xFFFF
		}
		// TCP_INITIAL_RTO_PARAMETERS { USHORT Rtt; UCHAR MaxSynRetransmissions; }
		var in [4]byte
		*(*uint16)(unsafe.Pointer(&in[0])) = uint16(ms)
		in[2] = tcpInitialRTONoSYNRetransmissions
		_ = c.Control(func(fd uintptr) {
			var ret uint32
			_ = windows.WSAIoctl(windows.Handle(fd), sioTCPInitialRTO, &in[0], uint32(len(in)), nil, 0, &ret, nil, 0)
		})
		return nil
	}
}
