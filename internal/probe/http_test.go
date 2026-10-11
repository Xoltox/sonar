package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestExtractTitle(t *testing.T) {
	long := strings.Repeat("a", 200)
	cases := []struct{ name, in, want string }{
		{"basic", "<html><head><title>Hello</title></head></html>", "Hello"},
		{"upper", "<HTML><TITLE>Router Login</TITLE>", "Router Login"},
		{"attrs", `<title id="x" lang=en>Attr</title>`, "Attr"},
		{"entities", "<title>A &amp; B &#39;c&#39;</title>", "A & B 'c'"},
		{"whitespace", "<title>\n  Foo \r\n\t  Bar\n</title>", "Foo Bar"},
		{"none", "<html><body>hi</body></html>", ""},
		{"empty", "<title>   </title>", ""},
		{"og", `<meta property="og:title" content="OG &amp; Co"><p>x</p>`, "OG & Co"},
		{"og single", `<meta content='Rev' property='og:title'>`, "Rev"},
		{"title wins", `<meta property="og:title" content="OG"><title>T</title>`, "T"},
		{"inner tags", "<title>A<b>B</b>C</title>", "ABC"},
		{"invalid utf8", "<title>ab\xff\xfecd</title>", "abcd"},
		{"control", "<title>a\x00b\x07c</title>", "abc"},
		{"long", "<title>" + long + "</title>", long[:120]},
		{"multibyte long", "<title>" + strings.Repeat("é", 200) + "</title>", strings.Repeat("é", 120)},
	}
	for _, c := range cases {
		if got := extractTitle([]byte(c.in)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func withPorts(t *testing.T, p []httpPort) {
	old := httpTitlePorts
	httpTitlePorts = p
	t.Cleanup(func() { httpTitlePorts = old })
}

func portOf(t *testing.T, s *httptest.Server) int {
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return p
}

var lo4 = netip.MustParseAddr("127.0.0.1")

func TestHTTPTitlePlain(t *testing.T) {
	var ua string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		fmt.Fprint(w, "<title>Plain</title>")
	}))
	defer s.Close()
	withPorts(t, []httpPort{{portOf(t, s), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "Plain" {
		t.Fatalf("got %q", got)
	}
	if !strings.HasPrefix(ua, "Sonar/1") {
		t.Fatalf("UA %q", ua)
	}
}

func TestHTTPTitleTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>Secure</title>")
	}))
	defer s.Close()
	withPorts(t, []httpPort{{portOf(t, s), "https"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "Secure" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPTitlePriority(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "<title>First</title>")
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>Second</title>")
	}))
	defer fast.Close()
	withPorts(t, []httpPort{{portOf(t, slow), "http"}, {portOf(t, fast), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "First" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPTitleFallsThroughEmpty(t *testing.T) {
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "no title")
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>B</title>")
	}))
	defer b.Close()
	withPorts(t, []httpPort{{portOf(t, a), "http"}, {1, "http"}, {portOf(t, b), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "B" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPTitleRedirects(t *testing.T) {
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/a", http.StatusFound)
		case "/a":
			fmt.Fprint(w, "<title>Followed</title>")
		}
	}))
	defer s.Close()
	withPorts(t, []httpPort{{portOf(t, s), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "Followed" {
		t.Fatalf("same-host: got %q", got)
	}

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<title>Elsewhere</title>")
	}))
	defer other.Close()
	away := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+strconv.Itoa(portOf(t, other))+"/", http.StatusFound)
	}))
	defer away.Close()
	withPorts(t, []httpPort{{portOf(t, away), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "" {
		t.Fatalf("cross-host redirect followed: %q", got)
	}

	// Too many redirects (loop) yields nothing.
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer loop.Close()
	withPorts(t, []httpPort{{portOf(t, loop), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "" {
		t.Fatalf("loop: %q", got)
	}
}

func TestHTTPTitleBodyLimit(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 70<<10)+"<title>Late</title>")
	}))
	defer s.Close()
	withPorts(t, []httpPort{{portOf(t, s), "http"}})
	if got := HTTPTitle(context.Background(), lo4, time.Second); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPTitleClosedPort(t *testing.T) {
	withPorts(t, []httpPort{{1, "http"}})
	if got := HTTPTitle(context.Background(), lo4, 300*time.Millisecond); got != "" {
		t.Fatalf("got %q", got)
	}
}
