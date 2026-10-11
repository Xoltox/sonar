package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/web"
)

const defaultServeAddr = "127.0.0.1:8080"

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// resolveBind normalizes a user-supplied listen address. An empty address or a
// missing host binds to loopback: the UI can trigger scans and Wake-on-LAN
// without authentication. explicit is true when the user named a non-loopback
// host.
func resolveBind(addr string) (listen, host string, explicit bool, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return defaultServeAddr, "127.0.0.1", false, nil
	}
	if !strings.Contains(addr, ":") {
		if _, perr := strconv.Atoi(addr); perr == nil {
			addr = ":" + addr
		} else {
			addr += ":8080"
		}
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", false, fmt.Errorf("invalid address %q: %v", addr, err)
	}
	if h == "" {
		h = "127.0.0.1"
	}
	return net.JoinHostPort(h, p), h, !isLoopbackHost(h), nil
}

// allowedHostsFor lists the Host header names the web UI accepts.
func allowedHostsFor(host string) []string {
	hosts := []string{"localhost", "127.0.0.1", "[::1]"}
	add := func(h string) {
		for _, x := range hosts {
			if x == h {
				return
			}
		}
		hosts = append(hosts, h)
	}
	switch host {
	case "0.0.0.0", "::":
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					add(ipn.IP.String())
				}
			}
		}
	default:
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		add(host)
	}
	return hosts
}

type serveOpts struct {
	addr   string
	open   bool
	cfg    web.Config
	banner func(url string) string // console line after bind; nil => default
	query  string                  // appended to the URL passed to the browser
}

// serveWeb runs the web UI until interrupted.
func serveWeb(o serveOpts) error {
	listen, host, explicit, err := resolveBind(o.addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	if explicit {
		fmt.Fprintf(os.Stderr, "sonar: warning: the web UI has no authentication; anyone who can reach %s can run scans and send Wake-on-LAN packets\n", listen)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	if explicit && host != "0.0.0.0" && host != "::" {
		url = "http://" + ln.Addr().String() + "/"
	}
	if o.banner != nil {
		fmt.Println(o.banner(url))
	} else {
		fmt.Println("Sonar web UI: " + url)
	}
	if o.open {
		if err := openBrowser(url + o.query); err != nil {
			fmt.Fprintf(os.Stderr, "sonar: note: could not open a browser (%v); open %s manually\n", err, url)
		}
	}

	srv := &http.Server{Handler: web.Handler(o.cfg, allowedHostsFor(host)), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	return nil
}

// setupLimits raises the file limit and caps concurrent dials.
func setupLimits() {
	maxDials := 512
	if lim, _ := probe.RaiseFileLimit(); lim > 0 && int(lim/2) < maxDials {
		maxDials = int(lim / 2)
	}
	probe.SetMaxDials(maxDials)
}

// parseFlags parses fs over args, allowing flags after positionals. It
// returns the positional arguments.
func parseFlags(fs *flag.FlagSet, args []string) (positional []string, help bool, err error) {
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("%v\nrun 'sonar -h' for usage", err)
		}
		if fs.NArg() == 0 {
			return positional, false, nil
		}
		if i := len(rest) - fs.NArg() - 1; i >= 0 && rest[i] == "--" {
			return append(positional, fs.Args()...), false, nil
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
}

// runServe implements `sonar serve [addr]` and `sonar ui`.
func runServe(args []string, ui bool) error {
	fs := flag.NewFlagSet("sonar serve", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	timeout := fs.Duration("timeout", 800*time.Millisecond, "per-probe timeout")
	concurrency := fs.Int("concurrency", 256, "parallel hosts")
	portSpec := fs.String("ports", "default", "ports to scan")
	open := fs.Bool("open", false, "open the browser")
	pos, help, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if help {
		fmt.Print(usageText)
		return nil
	}
	if len(pos) > 1 {
		return fmt.Errorf("serve takes at most one address")
	}
	addr := ""
	if len(pos) == 1 {
		addr = pos[0]
	}
	if ui {
		if addr == "" {
			addr = "127.0.0.1:0"
		}
		*open = true
	}
	query := ""
	if ui {
		query = "?scan=1"
	}
	return startWebQ(addr, *open, query, *timeout, *concurrency, *portSpec, nil)
}

func startWeb(addr string, open bool, timeout time.Duration, concurrency int, ports string, banner func(string) string) error {
	return startWebQ(addr, open, "", timeout, concurrency, ports, banner)
}

func startWebQ(addr string, open bool, query string, timeout time.Duration, concurrency int, ports string, banner func(string) string) error {
	if _, err := probe.ParsePorts(ports); err != nil {
		return err
	}
	setupLimits()
	return serveWeb(serveOpts{
		addr:   addr,
		open:   open,
		query:  query,
		banner: banner,
		cfg:    web.Config{Version: version, Timeout: timeout, Concurrency: concurrency, Ports: ports},
	})
}

// runDoubleClick starts the UI when sonar.exe was launched from Explorer.
func runDoubleClick() error {
	return startWebQ("127.0.0.1:0", true, "?scan=1", 800*time.Millisecond, 256, "default", func(url string) string {
		return fmt.Sprintf("Sonar is running at %s  -  close this window to quit.", url)
	})
}
