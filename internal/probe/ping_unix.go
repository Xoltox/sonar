//go:build linux || darwin

package probe

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	pingOnce sync.Once
	pingOK   bool
	pingHint string
)

func isPermErr(err error) bool {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permission denied") || strings.Contains(s, "operation not permitted")
}

func pingAvailable() (bool, string) {
	pingOnce.Do(func() {
		c, err := icmp.ListenPacket("udp4", "0.0.0.0")
		if err != nil {
			if isPermErr(err) && runtime.GOOS == "linux" {
				pingHint = `ICMP disabled for unprivileged users; to enable: sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"`
			} else if isPermErr(err) {
				pingHint = "ICMP not permitted for unprivileged users on this system"
			} else {
				pingHint = "ICMP unavailable: " + err.Error()
			}
			return
		}
		c.Close()
		pingOK = true
	})
	return pingOK, pingHint
}

func ping(ctx context.Context, addr netip.Addr, timeout time.Duration) (bool, time.Duration, error) {
	if !addr.Is4() {
		return false, 0, errors.New("icmp: only IPv4 supported")
	}
	release, err := acquire(ctx)
	if err != nil {
		return false, 0, nil
	}
	defer release()

	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false, 0, err
	}
	defer c.Close()

	id := rand.Intn(0xffff) + 1
	seq := rand.Intn(0xffff) + 1
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("sonar")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return false, 0, err
	}

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetDeadline(deadline)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-stop:
		}
	}()

	start := time.Now()
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: addr.AsSlice()}); err != nil {
		if isPermErr(err) {
			return false, 0, err
		}
		// Unreachable network and similar: no reply.
		return false, 0, nil
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return false, 0, nil
		}
		rtt := time.Since(start)
		var pa netip.Addr
		if ua, ok := peer.(*net.UDPAddr); ok {
			pa, _ = netip.AddrFromSlice(ua.IP)
			pa = pa.Unmap()
		}
		if pa != addr {
			continue
		}
		m, err := icmp.ParseMessage(1, rb[:n])
		if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		e, ok := m.Body.(*icmp.Echo)
		if !ok || e.Seq != seq {
			continue
		}
		if runtime.GOOS == "darwin" && e.ID != id {
			continue
		}
		return true, rtt, nil
	}
}
