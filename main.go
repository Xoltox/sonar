package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/Xoltox/sonar/internal/output"
	"github.com/Xoltox/sonar/internal/probe"
	"github.com/Xoltox/sonar/internal/scan"
	"github.com/Xoltox/sonar/internal/target"
)

var version = "dev"

const usageText = `sonar - fast LAN scanner

Usage:
  sonar [flags] [target ...]
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

Examples:
  sonar
  sonar 192.168.1.0/24
  sonar --ports 22,80,443 10.0.0.1-10.0.0.50
  sonar --json 192.168.1.0/24 > scan.json
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
		case "wol", "serve":
			fmt.Fprintf(os.Stderr, "sonar: %s: not implemented yet\n", args[0])
			os.Exit(2)
		}
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
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				fmt.Print(usageText)
				return nil
			}
			return fmt.Errorf("%v\nrun 'sonar -h' for usage", err)
		}
		if fs.NArg() == 0 {
			break
		}
		if i := len(rest) - fs.NArg() - 1; i >= 0 && rest[i] == "--" {
			positional = append(positional, fs.Args()...)
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if *asJSON && *asCSV {
		return fmt.Errorf("--json and --csv cannot be used together")
	}
	maxDials := 512
	if lim, _ := probe.RaiseFileLimit(); lim > 0 && int(lim/2) < maxDials {
		maxDials = int(lim / 2)
	}
	probe.SetMaxDials(maxDials)
	ports, err := probe.ParsePorts(*portSpec)
	if err != nil {
		return err
	}

	locals, err := target.LocalSubnets()
	if err != nil && len(positional) == 0 {
		return err
	}

	var targets []netip.Addr
	if len(positional) == 0 {
		if len(locals) == 0 {
			return fmt.Errorf("no local subnets found, give a target")
		}
		for _, l := range locals {
			fmt.Fprintf(os.Stderr, "Scanning %s (%s)\n", l.Prefix.Masked(), l.Iface)
		}
		if n := target.CountHosts(locals); n > target.MaxHostsDefault && !*force {
			return fmt.Errorf("local subnets expand to %d hosts, over the limit of %d; use --force to scan anyway", n, target.MaxHostsDefault)
		}
		targets = target.Hosts(locals)
	} else {
		targets, err = target.ParseAll(positional, *force)
		if err != nil {
			return err
		}
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

	progress := tableMode && isTTY(os.Stderr)

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
