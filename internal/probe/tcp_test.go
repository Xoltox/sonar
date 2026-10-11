package probe

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

var loopback = netip.MustParseAddr("127.0.0.1")

func listenAccept(t *testing.T) (int, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestTCPAliveRefused(t *testing.T) {
	alive, rtt := TCPAlive(context.Background(), loopback, []int{closedPort(t)}, time.Second)
	if !alive {
		t.Fatal("refused port should count as alive")
	}
	if rtt < 0 {
		t.Fatalf("bad rtt %v", rtt)
	}
}

func TestTCPAliveOpen(t *testing.T) {
	port, stop := listenAccept(t)
	defer stop()
	if alive, _ := TCPAlive(context.Background(), loopback, []int{port}, time.Second); !alive {
		t.Fatal("open port should be alive")
	}
}

func TestOpenPorts(t *testing.T) {
	port, stop := listenAccept(t)
	defer stop()
	got := OpenPorts(context.Background(), loopback, []int{closedPort(t), port}, time.Second)
	if !reflect.DeepEqual(got, []int{port}) {
		t.Fatalf("got %v want [%d]", got, port)
	}
}

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in   string
		want []int
		bad  bool
	}{
		{"", []int{}, false},
		{"none", []int{}, false},
		{"default", DefaultPorts, false},
		{"80,22,80", []int{22, 80}, false},
		{"1-3,10", []int{1, 2, 3, 10}, false},
		{"0", nil, true},
		{"65536", nil, true},
		{"5-3", nil, true},
		{"abc", nil, true},
		{"80,,22", nil, true},
	}
	for _, c := range cases {
		got, err := ParsePorts(c.in)
		if (err != nil) != c.bad {
			t.Errorf("%q: err=%v", c.in, err)
			continue
		}
		if !c.bad && (got == nil || !reflect.DeepEqual(got, c.want)) {
			t.Errorf("%q: got %v want %v", c.in, got, c.want)
		}
	}
	d, _ := ParsePorts("default")
	d[0] = 1
	if DefaultPorts[0] != 21 {
		t.Error("default must be a copy")
	}
}

func TestSetMaxDialsOne(t *testing.T) {
	SetMaxDials(1)
	defer SetMaxDials(defaultMaxDials)
	port, stop := listenAccept(t)
	defer stop()
	closed := closedPort(t)

	if alive, _ := TCPAlive(context.Background(), loopback, []int{closed, port}, time.Second); !alive {
		t.Fatal("TCPAlive should succeed with one dial slot")
	}
	got := OpenPorts(context.Background(), loopback, []int{closed, port, closed}, time.Second)
	if !reflect.DeepEqual(got, []int{port}) {
		t.Fatalf("got %v want [%d]", got, port)
	}
}

func TestCancelWhileSemaphoreHeld(t *testing.T) {
	SetMaxDials(1)
	defer SetMaxDials(defaultMaxDials)
	dialMu.RLock()
	sem := dialSem
	dialMu.RUnlock()
	sem <- struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	alive, _ := TCPAlive(ctx, loopback, []int{closedPort(t)}, 5*time.Second)
	open := OpenPorts(ctx, loopback, []int{closedPort(t)}, 5*time.Second)
	if alive || len(open) != 0 {
		t.Fatalf("expected nothing, got alive=%v open=%v", alive, open)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancel took %v", d)
	}
	<-sem
}

func TestDialPortRefusedFast(t *testing.T) {
	start := time.Now()
	_, err := dialPort(context.Background(), loopback, closedPort(t), 2*time.Second)
	if !isRefused(err) {
		t.Fatalf("want refused, got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("refusal took %v", d)
	}
}

func TestDialPortReleasesSlots(t *testing.T) {
	SetMaxDials(4)
	defer SetMaxDials(defaultMaxDials)
	port, stop := listenAccept(t)
	defer stop()
	for i := 0; i < 20; i++ {
		c, err := dialPort(context.Background(), loopback, port, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	// Every slot must be free again.
	deadline := time.Now().Add(2 * time.Second)
	for len(socketSem()) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d slots still held", len(socketSem()))
		}
		time.Sleep(10 * time.Millisecond)
	}
}
