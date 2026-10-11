package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Xoltox/sonar/internal/output"
	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/scan"
	"github.com/Xoltox/sonar/internal/target"
	"github.com/Xoltox/sonar/internal/wol"
)

var version = "dev"

const usageText = `sonar - fast LAN scanner

Usage:
  sonar [flags] [target ...]
  sonar serve [addr] [--open]
  sonar ui
  sonar wol <MAC> [MAC ...]
  sonar version
  sonar help

With no target, every local subnet is scanned.
Targets: 192.168.1.5, 192.168.1.0/24, 10.0.0.1-10.0.0.50, 10.0.0.1-50

Flags:
  --timeout duration    per-probe timeout (default 800ms)
  --concurrency int     parallel hosts (default 256)
  --ports string        ports to scan on live hosts: list, ranges, "default" or "none" (default "default")
  --all                 also show hosts that did not respond
  --json                JSON output
  --csv                 CSV output
  --no-color            disable colored output
  --force               allow scanning more than a /16
  --serve addr          start the web UI instead of scanning (uses --timeout, --concurrency, --ports)
  --open                open the web UI in the default browser (serve, --serve)

Web UI:
  sonar serve           web UI on 127.0.0.1:8080 (":8080" also binds loopback)
  sonar serve 0.0.0.0:8080
                        bind explicitly; the UI has no auth, so anyone who can
                        reach the address can run scans and send Wake-on-LAN
  sonar ui              web UI on a random loopback port, opens the browser
  sonar wol AA:BB:CC:DD:EE:FF
                        send a Wake-on-LAN magic packet

Examples:
  sonar
  sonar 192.168.1.0/24
  sonar --ports 22,80,443 10.0.0.1-10.0.0.50
  sonar --json 192.168.1.0/24 > scan.json
  sonar serve --open
  sonar --serve :0 --open
  sonar wol AA:BB:CC:DD:EE:FF
`

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version":
			fmt.Println("sonar " + version)
			return
		case "help", "-h", "--help", "-help":
			fmt.Print(usageText)
			return
		case "wol":
			os.Exit(runWOL(args[1:]))
		case "serve", "ui":
			if err := runServe(args[1:], args[0] == "ui"); err != nil {
				fmt.Fprintln(os.Stderr, "sonar: "+err.Error())
				os.Exit(1)
			}
			return
		}
	} else if isDoubleClick() {
		if err := runDoubleClick(); err != nil {
			fmt.Fprintln(os.Stderr, "sonar: "+err.Error())
			fmt.Fprintln(os.Stderr, "press Enter to close")
			fmt.Scanln()
			os.Exit(1)
		}
		return
	}
	if err := runScan(args); err != nil {
		fmt.Fprintln(os.Stderr, "sonar: "+err.Error())
		os.Exit(1)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("sonar", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	timeout := fs.Duration("timeout", 800*time.Millisecond, "per-probe timeout")
	concurrency := fs.Int("concurrency", 256, "parallel hosts")
	portSpec := fs.String("ports", "default", "ports to scan")
	all := fs.Bool("all", false, "show dead hosts too")
	asJSON := fs.Bool("json", false, "JSON output")
	asCSV := fs.Bool("csv", false, "CSV output")
	noColor := fs.Bool("no-color", false, "disable color")
	force := fs.Bool("force", false, "allow scans larger than a /16")
	serveAddr := fs.String("serve", "", "start the web UI on addr")
	open := fs.Bool("open", false, "open the browser")
	positional, help, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if help {
		fmt.Print(usageText)
		return nil
	}
	serving := false
	fs.Visit(func(f *flag.Flag) { serving = serving || f.Name == "serve" })
	if serving {
		return startWeb(*serveAddr, *open, *timeout, *concurrency, *portSpec, nil)
	}
	if *asJSON && *asCSV {
		return fmt.Errorf("--json and --csv cannot be used together")
	}
	setupLimits()
	ports, err := probe.ParsePorts(*portSpec)
	if err != nil {
		return err
	}

	targets, locals, desc, err := target.Resolve(positional, *force)
	if len(positional) == 0 {
		for _, d := range desc {
			fmt.Fprintf(os.Stderr, "Scanning %s\n", d)
		}
	}
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets")
	}

	tableMode := !*asJSON && !*asCSV
	var w output.Writer
	switch {
	case *asJSON:
		w = output.NewJSON(os.Stdout)
	case *asCSV:
		w = output.NewCSV(os.Stdout)
	default:
		w = output.NewTable(os.Stdout, !*noColor && output.ColorEnabled(os.Stdout))
	}

	if ok, hint := probe.PingAvailable(); !ok && hint != "" && (tableMode || isTTY(os.Stderr)) {
		fmt.Fprintln(os.Stderr, "sonar: note: "+hint)
	}

	progress := tableMode && isTTY(os.Stderr) && output.ColorEnabled(os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	start := time.Now()
	opts := scan.Options{
		Timeout:     *timeout,
		Concurrency: *concurrency,
		Ports:       ports,
		Locals:      locals,
	}

	var done, up int
	var werr error
	for r := range scan.Run(ctx, targets, opts) {
		done++
		if r.Alive {
			up++
		}
		if r.Alive || *all {
			if progress {
				clearLine(os.Stderr)
			}
			if err := w.Write(r); err != nil && werr == nil {
				werr = err
			}
		}
		if progress {
			fmt.Fprintf(os.Stderr, "\r %d/%d", done, len(targets))
		}
	}
	if progress {
		clearLine(os.Stderr)
	}
	if err := w.Close(); err != nil && werr == nil {
		werr = err
	}
	if tableMode {
		note := ""
		if ctx.Err() != nil {
			note = " (interrupted)"
		}
		fmt.Fprintf(os.Stderr, "%d scanned, %d up in %.1fs%s\n", done, up, time.Since(start).Seconds(), note)
	}
	return werr
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func clearLine(w io.Writer) {
	fmt.Fprint(w, "\r\x1b[2K")
}

func runWOL(macs []string) int {
	if len(macs) == 0 {
		fmt.Fprintln(os.Stderr, "sonar: wol: give at least one MAC address")
		return 1
	}
	code := 0
	for _, m := range macs {
		if err := wol.Send(m); err != nil {
			fmt.Fprintln(os.Stderr, "sonar: wol: "+err.Error())
			code = 1
			continue
		}
		hw, _ := net.ParseMAC(strings.TrimSpace(m))
		fmt.Printf("sent magic packet to %s\n", strings.ToUpper(hw.String()))
	}
	return code
}
