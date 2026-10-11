//go:build windows

package probe

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho2")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
)

// ICMP_ECHO_REPLY field offsets (identical on 32 and 64 bit up to RTT).
const (
	replyOffAddress = 0
	replyOffStatus  = 4
	replyOffRTT     = 8
)

func pingAvailable() (bool, string) {
	if err := procIcmpSendEcho.Find(); err != nil {
		return false, "ICMP unavailable: iphlpapi.dll not usable"
	}
	return true, ""
}

type pingResult struct {
	ok  bool
	rtt time.Duration
	err error
}

func ping(ctx context.Context, addr netip.Addr, timeout time.Duration) (bool, time.Duration, error) {
	if !addr.Is4() {
		return false, 0, errors.New("icmp: only IPv4 supported")
	}
	if ctx.Err() != nil {
		return false, 0, nil
	}
	if err := procIcmpSendEcho.Find(); err != nil {
		return false, 0, err
	}
	release, err := acquireBlocking(ctx)
	if err != nil {
		return false, 0, nil
	}
	ms := timeout.Milliseconds()
	if dl, has := ctx.Deadline(); has {
		if r := time.Until(dl).Milliseconds(); r < ms {
			ms = r
		}
	}
	if ms < 1 {
		ms = 1
	}
	// IcmpSendEcho2 blocks its thread until a reply or the timeout and cannot
	// be cancelled, so it runs in its own goroutine that owns the slot; the
	// caller returns as soon as ctx is done.
	ch := make(chan pingResult, 1)
	go func() {
		defer release()
		ok, rtt, err := icmpEcho(addr, uint32(ms))
		ch <- pingResult{ok, rtt, err}
	}()
	select {
	case r := <-ch:
		return r.ok, r.rtt, r.err
	case <-ctx.Done():
		return false, 0, nil
	}
}

func icmpEcho(addr netip.Addr, ms uint32) (bool, time.Duration, error) {
	// One handle per call: no sharing assumptions.
	h, _, callErr := procIcmpCreate.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return false, 0, callErr
	}
	defer procIcmpClose.Call(h)

	a4 := addr.As4()
	// IPAddr is a uint32 in network byte order, i.e. memory order a4[0..3].
	dest := *(*uint32)(unsafe.Pointer(&a4[0]))
	data := [32]byte{'s', 'o', 'n', 'a', 'r'}
	var reply [512]byte

	start := time.Now()
	n, _, _ := procIcmpSendEcho.Call(
		h, 0, 0, 0,
		uintptr(dest),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)),
		uintptr(ms),
	)
	elapsed := time.Since(start)
	if n == 0 {
		return false, 0, nil
	}
	gotAddr := *(*uint32)(unsafe.Pointer(&reply[replyOffAddress]))
	status := *(*uint32)(unsafe.Pointer(&reply[replyOffStatus]))
	rttMs := *(*uint32)(unsafe.Pointer(&reply[replyOffRTT]))
	if status != 0 || gotAddr != dest {
		return false, 0, nil
	}
	rtt := time.Duration(rttMs) * time.Millisecond
	if rttMs == 0 {
		rtt = elapsed
	}
	return true, rtt, nil
}
