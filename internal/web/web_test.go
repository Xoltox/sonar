package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xoltox/sonar/internal/scan"
)

var testCfg = Config{Version: "test", Timeout: 500 * time.Millisecond, Concurrency: 4, Ports: "none"}

func testHandler() http.Handler {
	_, h := newServer(testCfg, []string{"127.0.0.1", "localhost"})
	return h
}

// testSrv returns a handler and its token.
func testSrv() (*server, http.Handler, string) {
	s, h := newServer(testCfg, []string{"127.0.0.1", "localhost"})
	return s, h, s.token
}

func tok(t string) map[string]string { return map[string]string{"X-Sonar-Token": t} }

func do(h http.Handler, method, path, host string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestIndex(t *testing.T) {
	rec := do(testHandler(), "GET", "/", "127.0.0.1:8080", nil, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("code %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("missing CSP")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing XFO")
	}
	if strings.ContainsRune(rec.Body.String(), rune(0x2013)) || strings.ContainsRune(rec.Body.String(), rune(0x2014)) {
		t.Fatal("index.html contains en/em dash")
	}
}

var metaRe = regexp.MustCompile(`<meta name="sonar-token" content="([0-9a-f]{64})">`)

func TestIndexToken(t *testing.T) {
	a := do(testHandler(), "GET", "/", "127.0.0.1", nil, "").Body.String()
	b := do(testHandler(), "GET", "/", "127.0.0.1", nil, "").Body.String()
	ma, mb := metaRe.FindStringSubmatch(a), metaRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		t.Fatal("no token meta in index")
	}
	if ma[1] == mb[1] {
		t.Fatal("tokens must differ per Handler")
	}
	if strings.Contains(a, tokenPlaceholder) {
		t.Fatal("placeholder left in page")
	}
}

func TestAPIToken(t *testing.T) {
	_, h, tk := testSrv()
	const scanURL = "/api/scan?targets=127.0.0.1&ports=none"
	if rec := do(h, "GET", scanURL, "127.0.0.1", nil, ""); rec.Code != 403 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(h, "GET", scanURL, "127.0.0.1", tok("wrong"), ""); rec.Code != 403 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	rec := do(h, "GET", scanURL, "127.0.0.1", tok(tk), "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "event: done") {
		t.Fatalf("header token: %d %q", rec.Code, rec.Body.String())
	}
	rec = do(h, "GET", scanURL+"&token="+tk, "127.0.0.1", nil, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "event: done") {
		t.Fatalf("query token: %d", rec.Code)
	}
	h2 := tok(tk)
	h2["Sec-Fetch-Site"] = "cross-site"
	if rec := do(h, "GET", scanURL, "127.0.0.1", h2, ""); rec.Code != 403 {
		t.Fatalf("cross-site: %d", rec.Code)
	}
	h2["Sec-Fetch-Site"] = "same-origin"
	if rec := do(h, "GET", "/api/info", "127.0.0.1", h2, ""); rec.Code != 200 {
		t.Fatalf("same-origin: %d", rec.Code)
	}
	h3 := tok(tk)
	h3["Origin"] = "http://evil.example"
	if rec := do(h, "GET", "/api/info", "127.0.0.1", h3, ""); rec.Code != 403 {
		t.Fatalf("origin mismatch on GET: %d", rec.Code)
	}
	h3["Origin"] = "http://127.0.0.1"
	if rec := do(h, "GET", "/api/info", "127.0.0.1", h3, ""); rec.Code != 200 {
		t.Fatalf("origin match: %d", rec.Code)
	}
}

func TestHeadersOnJSON(t *testing.T) {
	_, h, tk := testSrv()
	rec := do(h, "GET", "/api/info", "127.0.0.1", tok(tk), "")
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" ||
		rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", rec.Header())
	}
	if rec := do(h, "GET", "/api/info", "127.0.0.1", nil, ""); rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff missing on 403")
	}
}

func TestScanPortCap(t *testing.T) {
	_, h, tk := testSrv()
	rec := do(h, "GET", "/api/scan?targets=127.0.0.1&ports=1-2000&token="+tk, "127.0.0.1", nil, "")
	evs := parseSSE(rec.Body.String())
	if len(evs) != 1 || evs[0].name != "error" || !strings.Contains(evs[0].data, "too many ports") {
		t.Fatalf("got %q", rec.Body.String())
	}
}

func TestScanNoOverlap(t *testing.T) {
	s, h, tk := testSrv()
	var active, maxActive, started int32
	s.run = func(ctx context.Context, targets []netip.Addr, o scan.Options) <-chan scan.Result {
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxActive)
			if n <= m || atomic.CompareAndSwapInt32(&maxActive, m, n) {
				break
			}
		}
		atomic.AddInt32(&started, 1)
		out := make(chan scan.Result)
		go func() {
			defer close(out)
			defer atomic.AddInt32(&active, -1)
			select {
			case <-ctx.Done():
				time.Sleep(50 * time.Millisecond) // slow drain
			case <-time.After(300 * time.Millisecond):
			}
		}()
		return out
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do(h, "GET", "/api/scan?targets=127.0.0.1&ports=none&token="+tk, "127.0.0.1", nil, "")
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	if m := atomic.LoadInt32(&maxActive); m != 1 {
		t.Fatalf("max concurrent scans = %d, want 1", m)
	}
	if atomic.LoadInt32(&started) < 2 {
		t.Fatal("expected several scans to start")
	}
}

func TestWrongHost(t *testing.T) {
	if rec := do(testHandler(), "GET", "/", "evil.example:8080", nil, ""); rec.Code != 403 {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestWOLOrigin(t *testing.T) {
	_, h, tk := testSrv()
	rec := do(h, "POST", "/api/wol", "127.0.0.1:8080",
		map[string]string{"Origin": "http://evil.example", "Content-Type": "application/json", "X-Sonar-Token": tk}, `{"mac":"aa:bb:cc:dd:ee:ff"}`)
	if rec.Code != 403 {
		t.Fatalf("got %d", rec.Code)
	}
	rec = do(h, "POST", "/api/wol", "127.0.0.1:8080",
		map[string]string{"Content-Type": "text/plain", "X-Sonar-Token": tk}, `{}`)
	if rec.Code == 204 || rec.Code == 200 {
		t.Fatalf("content type not enforced: %d", rec.Code)
	}
	rec = do(h, "POST", "/api/wol", "127.0.0.1:8080",
		map[string]string{"Content-Type": "application/json", "X-Sonar-Token": tk}, `{"mac":"nonsense"}`)
	if rec.Code != 400 {
		t.Fatalf("bad mac: got %d", rec.Code)
	}
}

func TestRDP(t *testing.T) {
	_, h, tk := testSrv()
	for _, bad := range []string{"", "nope", "::1", "1.2.3.4/24"} {
		if rec := do(h, "GET", "/api/rdp?token="+tk+"&ip="+bad, "127.0.0.1", nil, ""); rec.Code != 400 {
			t.Errorf("ip %q: got %d", bad, rec.Code)
		}
	}
	rec := do(h, "GET", "/api/rdp?ip=10.0.0.5&token="+tk, "127.0.0.1", nil, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "full address:s:10.0.0.5") {
		t.Fatalf("bad rdp: %d %q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "10.0.0.5.rdp") {
		t.Fatalf("disposition %q", cd)
	}
}

type sseEvent struct{ name, data string }

func parseSSE(body string) []sseEvent {
	var evs []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			cur.name = line[7:]
		case strings.HasPrefix(line, "data: "):
			cur.data = line[6:]
		case line == "" && cur.name != "":
			evs = append(evs, cur)
			cur = sseEvent{}
		}
	}
	return evs
}

func TestScanStream(t *testing.T) {
	_, h, tk := testSrv()
	rec := do(h, "GET", "/api/scan?targets=127.0.0.1&ports=none", "127.0.0.1", tok(tk), "")
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	evs := parseSSE(rec.Body.String())
	idx := map[string]int{}
	for i, e := range evs {
		if _, ok := idx[e.name]; !ok {
			idx[e.name] = i
		}
	}
	s, okS := idx["start"]
	r, okR := idx["result"]
	d, okD := idx["done"]
	if !okS || !okR || !okD || !(s < r && r < d) {
		t.Fatalf("bad event order: %+v", evs)
	}
	if !strings.Contains(evs[r].data, `"127.0.0.1"`) || !strings.Contains(evs[r].data, `"alive":true`) {
		t.Fatalf("result: %s", evs[r].data)
	}
}

func TestScanBadTarget(t *testing.T) {
	_, h, tk := testSrv()
	rec := do(h, "GET", "/api/scan?targets=not-a-target!!", "127.0.0.1", tok(tk), "")
	evs := parseSSE(rec.Body.String())
	if rec.Code != 400 && (len(evs) == 0 || evs[0].name != "error") {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
}

// TestServe serves the UI for manual inspection:
// SONAR_SERVE=1 go test -run TestServe ./internal/web
func TestServe(t *testing.T) {
	if os.Getenv("SONAR_SERVE") != "1" {
		t.Skip("set SONAR_SERVE=1 to serve the UI on 127.0.0.1:8765 for 60s")
	}
	h := Handler(Config{Version: "dev", Timeout: time.Second, Concurrency: 128, Ports: "default"},
		[]string{"127.0.0.1", "localhost"})
	srv := &http.Server{Addr: "127.0.0.1:8765", Handler: h}
	go func() { _ = srv.ListenAndServe() }()
	time.Sleep(60 * time.Second)
	_ = srv.Close()
}
