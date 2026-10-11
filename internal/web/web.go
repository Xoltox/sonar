// Package web serves the Sonar browser UI and its JSON/SSE API.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/scan"
	"github.com/Xoltox/sonar/internal/target"
	"github.com/Xoltox/sonar/internal/wol"
)

//go:embed index.html
var indexHTML []byte

// Config holds the defaults the UI starts with.
type Config struct {
	Version     string
	Timeout     time.Duration
	Concurrency int
	Ports       string // default port spec, e.g. "default"
}

const (
	tokenPlaceholder = "__SONAR_TOKEN__"
	maxWebPorts      = 1024
	maxWebWork       = 65536 * 32 // hosts * ports per request
	drainTimeout     = 5 * time.Second
)

type scanRunner func(ctx context.Context, targets []netip.Addr, o scan.Options) <-chan scan.Result

type server struct {
	cfg   Config
	token string
	page  []byte
	run   scanRunner // scan.Run; replaceable in tests

	startMu sync.Mutex // serializes cancel-old / wait / start-new

	mu     sync.Mutex
	cancel context.CancelFunc // cancels the running scan, if any
	done   chan struct{}      // closed when the running scan has fully drained
}

// Handler returns the UI + API. allowedHosts are Host header values accepted
// (DNS-rebinding guard).
func Handler(cfg Config, allowedHosts []string) http.Handler {
	_, h := newServer(cfg, allowedHosts)
	return h
}

func newServer(cfg Config, allowedHosts []string) (*server, http.Handler) {
	tb := make([]byte, 32)
	if _, err := rand.Read(tb); err != nil {
		panic("sonar: crypto/rand failed: " + err.Error())
	}
	s := &server{cfg: cfg, token: hex.EncodeToString(tb), run: scan.Run}
	s.page = bytes.Replace(indexHTML, []byte(tokenPlaceholder), []byte(s.token), 1)
	allowed := make(map[string]bool, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[strings.ToLower(hostOnly(h))] = true
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/info", s.info)
	mux.HandleFunc("/api/scan", s.scan)
	mux.HandleFunc("/api/wol", s.wol)
	mux.HandleFunc("/api/rdp", s.rdp)
	return s, s.guard(allowed, mux)
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

func (s *server) guard(allowed map[string]bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Referrer-Policy", "no-referrer")
		if !allowed[strings.ToLower(hostOnly(r.Host))] {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
				http.Error(w, "forbidden cross-site request", http.StatusForbidden)
				return
			}
			if o := r.Header.Get("Origin"); o != "" && !strings.EqualFold(o, "http://"+r.Host) {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			tok := r.Header.Get("X-Sonar-Token")
			if tok == "" {
				tok = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
				http.Error(w, "forbidden: missing or invalid token", http.StatusForbidden)
				return
			}
		}
		if r.Method == http.MethodPost {
			ct := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			if ct != "application/json" {
				http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	_, _ = w.Write(s.page)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *server) info(w http.ResponseWriter, r *http.Request) {
	_, _, desc, _ := target.Resolve(nil, false)
	if desc == nil {
		desc = []string{}
	}
	writeJSON(w, map[string]any{"version": s.cfg.Version, "targets_default": desc, "ports_default": s.cfg.Ports})
}

// sseWriter writes Server-Sent Events and flushes after each one.
type sseWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (e sseWriter) send(event string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	fmt.Fprintf(e.w, "event: %s\ndata: %s\n\n", event, b)
	e.f.Flush()
}

func splitSpecs(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == ';'
	})
}

func (s *server) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	sse := sseWriter{w: w, f: f}

	q := r.URL.Query()
	hosts, locals, desc, err := target.Resolve(splitSpecs(q.Get("targets")), false)
	if err != nil {
		sse.send("error", map[string]string{"message": err.Error()})
		return
	}
	spec := q.Get("ports")
	if strings.TrimSpace(spec) == "" {
		spec = s.cfg.Ports
	}
	ports, err := probe.ParsePorts(spec)
	if err != nil {
		sse.send("error", map[string]string{"message": err.Error()})
		return
	}
	if len(ports) > maxWebPorts {
		sse.send("error", map[string]string{"message": fmt.Sprintf("too many ports (%d); the web UI allows at most %d", len(ports), maxWebPorts)})
		return
	}
	if len(hosts)*len(ports) > maxWebWork {
		sse.send("error", map[string]string{"message": fmt.Sprintf("scan too large (%d hosts x %d ports); narrow the targets or ports", len(hosts), len(ports))})
		return
	}
	all := q.Get("all") == "1"

	// One scan at a time: cancel the previous scan and wait for it to drain.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	myDone := make(chan struct{})
	s.startMu.Lock()
	s.mu.Lock()
	oldCancel, oldDone := s.cancel, s.done
	s.mu.Unlock()
	if oldCancel != nil {
		oldCancel()
		select {
		case <-oldDone:
		case <-time.After(drainTimeout):
			s.startMu.Unlock()
			sse.send("error", map[string]string{"message": "previous scan is still stopping; try again"})
			return
		case <-r.Context().Done():
			s.startMu.Unlock()
			return
		}
	}
	s.mu.Lock()
	s.cancel, s.done = cancel, myDone
	s.mu.Unlock()
	s.startMu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.done == myDone {
			s.cancel, s.done = nil, nil
		}
		s.mu.Unlock()
		close(myDone)
	}()

	if desc == nil {
		desc = []string{}
	}
	total := len(hosts)
	sse.send("start", map[string]any{"total": total, "ranges": desc})

	began := time.Now()
	results := s.run(ctx, hosts, scan.Options{
		Timeout:     s.cfg.Timeout,
		Concurrency: s.cfg.Concurrency,
		Ports:       ports,
		Locals:      locals,
	})
	done, up := 0, 0
	lastProgress := time.Now()
	for res := range results {
		done++
		if res.Alive {
			up++
		}
		if res.Alive || all {
			sse.send("result", res)
		}
		if time.Since(lastProgress) >= 100*time.Millisecond {
			lastProgress = time.Now()
			sse.send("progress", map[string]int{"done": done, "total": total})
		}
	}
	if ctx.Err() != nil {
		return // cancelled by client or by a newer scan
	}
	sse.send("progress", map[string]int{"done": done, "total": total})
	sse.send("done", map[string]any{"scanned": done, "up": up, "elapsed_ms": time.Since(began).Milliseconds()})
}

func (s *server) wol(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		MAC string `json:"mac"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := wol.Send(body.MAC); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) rdp(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
	if err != nil || !ip.Is4() {
		http.Error(w, "invalid IPv4 address", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", ip.String()+".rdp"))
	fmt.Fprintf(w, "full address:s:%s\r\nprompt for credentials:i:1\r\nscreen mode id:i:2\r\nauthentication level:i:2\r\nredirectclipboard:i:1\r\n", ip)
}
