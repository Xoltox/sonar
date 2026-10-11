package probe

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	httpUserAgent    = "Sonar/1 (+https://github.com/Xoltox/sonar)"
	httpTotalTimeout = 1500 * time.Millisecond
	httpMaxBody      = 64 << 10
	httpMaxTitle     = 120
	httpMaxRedirect  = 2
)

type httpPort struct {
	port   int
	scheme string
}

// httpTitlePorts is the priority-ordered list HTTPTitle tries. Tests override it.
var httpTitlePorts = []httpPort{{80, "http"}, {8080, "http"}, {443, "https"}, {8443, "https"}}

// HTTPTitle tries the HTTP(S) ports concurrently and returns the title from
// the highest-priority port that yields one, or "".
func HTTPTitle(ctx context.Context, addr netip.Addr, connectTimeout time.Duration) string {
	ports := httpTitlePorts
	if len(ports) == 0 {
		return ""
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type res struct {
		i     int
		title string
	}
	ch := make(chan res, len(ports))
	for i, p := range ports {
		go func(i int, p httpPort) {
			ch <- res{i, httpTitleOne(ctx, addr, p, connectTimeout)}
		}(i, p)
	}
	done := make([]bool, len(ports))
	titles := make([]string, len(ports))
	for n := 0; n < len(ports); n++ {
		r := <-ch
		done[r.i], titles[r.i] = true, r.title
		for i := range ports {
			if !done[i] {
				break
			}
			if titles[i] != "" {
				return titles[i]
			}
		}
	}
	return ""
}

func httpTitleOne(ctx context.Context, addr netip.Addr, p httpPort, connectTimeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, httpTotalTimeout)
	defer cancel()
	// The slot is held for the whole attempt, covering every socket it opens.
	release, err := acquire(ctx)
	if err != nil {
		return ""
	}
	defer release()

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: connectTimeout, Control: dialControl(time.Now().Add(connectTimeout))}
			return d.DialContext(ctx, network, address)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: httpTotalTimeout,
		TLSHandshakeTimeout:   httpTotalTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10},
	}
	defer tr.CloseIdleConnections()
	host := addr.String()
	client := &http.Client{
		Transport: tr,
		Timeout:   httpTotalTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > httpMaxRedirect || req.URL.Hostname() != host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	u := p.scheme + "://" + net.JoinHostPort(host, strconv.Itoa(p.port)) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", httpUserAgent)
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, httpMaxBody))
	return extractTitle(body)
}

var (
	titleRe   = regexp.MustCompile(`(?is)<title(?:\s[^>]*)?>(.*?)</title\s*>`)
	metaRe    = regexp.MustCompile(`(?is)<meta\s[^>]*>`)
	attrRe    = regexp.MustCompile(`(?is)([a-zA-Z:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
	tagStripR = regexp.MustCompile(`(?s)<[^>]*>`)
)

// extractTitle returns the cleaned page title, falling back to og:title.
func extractTitle(body []byte) string {
	s := strings.ToValidUTF8(string(body), "")
	if m := titleRe.FindStringSubmatch(s); m != nil {
		if t := cleanTitle(m[1]); t != "" {
			return t
		}
	}
	for _, tag := range metaRe.FindAllString(s, -1) {
		var prop, content string
		for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
			v := a[2] + a[3] + a[4]
			switch strings.ToLower(a[1]) {
			case "property", "name":
				prop = strings.ToLower(v)
			case "content":
				content = v
			}
		}
		if prop == "og:title" {
			if t := cleanTitle(content); t != "" {
				return t
			}
		}
	}
	return ""
}

func cleanTitle(raw string) string {
	t := html.UnescapeString(raw)
	t = tagStripR.ReplaceAllString(t, "")
	t = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), r == unicode.ReplacementChar:
			return -1
		}
		return r
	}, t)
	t = strings.Join(strings.Fields(t), " ")
	if rs := []rune(t); len(rs) > httpMaxTitle {
		t = strings.TrimSpace(string(rs[:httpMaxTitle]))
	}
	return t
}
