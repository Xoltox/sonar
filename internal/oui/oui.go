// Package oui maps MAC address prefixes to short vendor names using an
// embedded, gzip-compressed copy of the IEEE MA-L registry.
package oui

//go:generate go run ./gen

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed oui.txt.gz
var tableGz []byte

var (
	once  sync.Once
	table map[uint32]string
)

func load() {
	table = make(map[uint32]string, 40000)
	zr, err := gzip.NewReader(bytes.NewReader(tableGz))
	if err != nil {
		return
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 8 || line[6] != '\t' {
			continue
		}
		v, err := strconv.ParseUint(line[:6], 16, 32)
		if err != nil {
			continue
		}
		table[uint32(v)] = line[7:]
	}
}

// size returns the number of entries in the embedded table.
func size() int {
	once.Do(load)
	return len(table)
}

// Lookup returns the short vendor name for a MAC like "AA:BB:CC:DD:EE:FF"
// (also accepts "-" separators and lowercase), or "" if unknown, invalid, or
// the MAC is locally administered (bit 0x02 of the first octet set).
func Lookup(mac string) string {
	mac = strings.TrimSpace(mac)
	if len(mac) < 8 {
		return ""
	}
	var b [3]byte
	for i := 0; i < 3; i++ {
		p := i * 3
		if i > 0 && mac[p-1] != ':' && mac[p-1] != '-' {
			return ""
		}
		hi, ok1 := hexVal(mac[p])
		lo, ok2 := hexVal(mac[p+1])
		if !ok1 || !ok2 {
			return ""
		}
		b[i] = hi<<4 | lo
	}
	if len(mac) > 8 && mac[8] != ':' && mac[8] != '-' {
		return ""
	}
	if b[0]&0x02 != 0 {
		return ""
	}
	once.Do(load)
	return table[uint32(b[0])<<16|uint32(b[1])<<8|uint32(b[2])]
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
