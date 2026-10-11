// Command gen downloads the IEEE MA-L registry and writes oui.txt.gz.
package main

import (
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	csvURL = "https://standards-oui.ieee.org/oui/oui.csv"
	txtURL = "https://standards-oui.ieee.org/oui/oui.txt"
	ua     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

func main() {
	in := flag.String("in", "", "local oui.csv or oui.txt file instead of downloading")
	out := flag.String("out", "", "output path (default: oui.txt.gz in cwd, or internal/oui from repo root)")
	flag.Parse()

	entries, err := fetch(*in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	if len(entries) < 1000 {
		fmt.Fprintf(os.Stderr, "gen: only %d entries parsed, refusing to write\n", len(entries))
		os.Exit(1)
	}
	path := *out
	if path == "" {
		path = "oui.txt.gz"
		if _, err := os.Stat("oui.go"); err != nil {
			if _, err2 := os.Stat(filepath.Join("internal", "oui", "oui.go")); err2 == nil {
				path = filepath.Join("internal", "oui", "oui.txt.gz")
			}
		}
	}
	if err := write(path, entries); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d entries to %s\n", len(entries), path)
}

func fetch(in string) (map[string]string, error) {
	if in != "" {
		data, err := os.ReadFile(in)
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(strings.ToLower(in), ".txt") {
			return parseTXT(string(data)), nil
		}
		return parseCSV(string(data))
	}
	body, err := get(csvURL)
	if err == nil {
		var m map[string]string
		if m, err = parseCSV(body); err == nil && len(m) > 1000 {
			return m, nil
		}
	}
	fmt.Fprintln(os.Stderr, "gen: csv failed, trying txt:", err)
	body, err2 := get(txtURL)
	if err2 != nil {
		return nil, fmt.Errorf("download failed: csv: %v; txt: %v", err, err2)
	}
	return parseTXT(body), nil
}

func get(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")
	c := &http.Client{Timeout: 120 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func parseCSV(s string) (map[string]string, error) {
	s = strings.TrimPrefix(s, string(rune(0xFEFF)))
	r := csv.NewReader(strings.NewReader(s))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string, len(recs))
	for _, rec := range recs {
		if len(rec) < 3 {
			continue
		}
		p := strings.ToUpper(strings.TrimSpace(rec[1]))
		if !validPrefix(p) {
			continue
		}
		if n := shortName(rec[2]); n != "" {
			m[p] = n
		}
	}
	return m, nil
}

func parseTXT(s string) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(s, "\n") {
		i := strings.Index(line, "(hex)")
		if i < 0 {
			continue
		}
		p := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(line[:i]), "-", ""))
		if !validPrefix(p) {
			continue
		}
		if n := shortName(line[i+5:]); n != "" {
			m[p] = n
		}
	}
	return m
}

func validPrefix(p string) bool {
	if len(p) != 6 {
		return false
	}
	for _, c := range p {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func write(path string, m map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return err
	}
	for _, k := range keys {
		if _, err := fmt.Fprintf(zw, "%s\t%s\n", k, m[k]); err != nil {
			f.Close()
			return err
		}
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func wordSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// Legal forms and generic corporate words, dropped from the end of a name.
var suffixes = wordSet(
	"co", "ltd", "limited", "inc", "incorporated", "corporation", "corporate", "corp",
	"llc", "gmbh", "ag", "sa", "bv", "nv", "pty", "plc", "oy", "ab", "as", "a/s",
	"spa", "sas", "kg", "company", "technologies", "technology", "tech",
	"electronics", "electronic", "international", "industrial", "industries",
	"industry", "ind", "holdings", "group", "systems", "r&d", "and", "of",
	// Descriptive words.
	"mobile", "communication", "communications", "telecom", "telecommunication",
	"telecommunications", "network", "networks", "networking", "digital",
	"software", "information", "intelligent", "smart", "science", "sci",
	"pte", "pvt", "srl", "bhd", "sdn", "kft", "ooo", "aps", "private",
)

// Location prefixes common in IEEE registrations.
var locations = wordSet(
	"shenzhen", "guangdong", "guangzhou", "beijing", "shanghai", "hangzhou",
	"zhejiang", "jiangsu", "suzhou", "xiamen", "fujian", "dongguan", "chengdu",
	"wuhan", "qingdao", "ningbo", "nanjing",
)

type override struct{ key, name string }

var overrides = []override{
	{"hewlett packard enterprise", "HPE"},
	{"hewlett packard", "HP"},
	{"hewlett-packard", "HP"},
	{"cloud network technology singapore", "Foxconn"},
	{"universal global scientific", "USI"},
	{"amazon technologies", "Amazon"},
	{"texas instruments", "TI"},
	{"sony interactive", "Sony"},
	{"intel corporate", "Intel"},
	{"lg electronics", "LG"},
	{"lg innotek", "LG"},
	{"raspberry pi", "Raspberry Pi"},
	{"nest labs", "Google Nest"},
	{"ring llc", "Ring"},
	{"micro-star", "Micro-Star"},
	{"hon hai", "Foxconn"},
	{"foxconn", "Foxconn"},
	{"routerboard", "MikroTik"},
	{"mikrotik", "MikroTik"},
	{"azurewave", "AzureWave"},
	{"espressif", "Espressif"},
	{"ubiquiti", "Ubiquiti"},
	{"synology", "Synology"},
	{"microsoft", "Microsoft"},
	{"hikvision", "Hikvision"},
	{"sagemcom", "Sagemcom"},
	{"arcadyan", "Arcadyan"},
	{"nintendo", "Nintendo"},
	{"giga-byte", "Gigabyte"},
	{"gigabyte", "Gigabyte"},
	{"samsung", "Samsung"},
	{"realtek", "Realtek"},
	{"netgear", "Netgear"},
	{"tp-link", "TP-Link"},
	{"asustek", "ASUS"},
	{"oneplus", "OnePlus"},
	{"lite-on", "Lite-On"},
	{"liteon", "Lite-On"},
	{"murata", "Murata"},
	{"huawei", "Huawei"},
	{"lenovo", "Lenovo"},
	{"xiaomi", "Xiaomi"},
	{"google", "Google"},
	{"amazon", "Amazon"},
	{"realme", "realme"},
	{"asrock", "ASRock"},
	{"meizu", "Meizu"},
	{"honor", "Honor"},
	{"dahua", "Dahua"},
	{"apple", "Apple"},
	{"intel", "Intel"},
	{"cisco", "Cisco"},
	{"sonos", "Sonos"},
	{"oppo", "OPPO"},
	{"vivo", "vivo"},
	{"tuya", "Tuya"},
	{"lcfc", "Lenovo"},
	{"roku", "Roku"},
	{"qnap", "QNAP"},
	{"asus", "ASUS"},
	{"sony", "Sony"},
	{"dell", "Dell"},
	{"zte", "ZTE"},
	{"avm", "AVM"},
	{"hp", "HP"},
}

func init() {
	// Longest keys first so more specific names win.
	sort.SliceStable(overrides, func(i, j int) bool { return len(overrides[i].key) > len(overrides[j].key) })
}

func hasWordPrefix(s, key string) bool {
	if !strings.HasPrefix(s, key) {
		return false
	}
	if len(s) == len(key) {
		return true
	}
	c := rune(s[len(key)])
	return !(unicode.IsLetter(c) || unicode.IsDigit(c))
}

func normalize(s string) string {
	s = strings.NewReplacer("\u2013", "-", "\u2014", "-", "\u2012", "-", "\u2212", "-").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

var (
	reParen  = regexp.MustCompile(`\([^)]*\)?`)
	reAmpCo  = regexp.MustCompile(`(?i)\s*&\s*co\b`)
	reRD     = regexp.MustCompile(`(?i)\bR\s*&\s*D\b`)
	dotComma = strings.NewReplacer(",", " ", ".", " ")
)

func shortName(org string) string {
	org = normalize(org)
	if org == "" {
		return ""
	}
	clean := reParen.ReplaceAllString(org, " ")
	clean = reAmpCo.ReplaceAllString(clean, " ")
	clean = reRD.ReplaceAllString(clean, "R&D")
	words := cleanWords(dotComma.Replace(clean))
	if len(words) == 0 {
		words = cleanWords(dotComma.Replace(org))
		if len(words) == 0 {
			return strings.Trim(org, " ,.-&")
		}
	}
	// Leading location tokens, only when something remains.
	for len(words) > 1 {
		lw := strings.ToLower(words[0])
		if locations[lw] {
			words = words[1:]
		} else if lw == "hong" && len(words) > 2 && strings.EqualFold(words[1], "kong") {
			words = words[2:]
		} else {
			break
		}
	}
	low := strings.ToLower(strings.Join(words, " "))
	for _, o := range overrides {
		if hasWordPrefix(low, o.key) {
			return o.name
		}
	}
	// Trailing legal and descriptive words, at most 3 words, at most 24
	// runes; never cut mid-word. Repeat since trimming can expose suffixes.
	for {
		n := len(words)
		for len(words) > 1 && suffixes[strings.ToLower(words[len(words)-1])] {
			words = words[:len(words)-1]
		}
		if len(words) > 3 {
			words = words[:3]
		}
		for len(words) > 1 && len([]rune(strings.Join(words, " "))) > 24 {
			words = words[:len(words)-1]
		}
		if len(words) == n {
			break
		}
	}
	name := strings.Join(words, " ")
	if name == strings.ToLower(name) {
		name = capWords(name)
	} else if len([]rune(name)) > 4 && name == strings.ToUpper(name) {
		name = titleCase(name)
	}
	return strings.Trim(name, " ,.-&")
}

// cleanWords splits on spaces, trims stray punctuation, and drops empties.
func cleanWords(s string) []string {
	var out []string
	for _, w := range strings.Fields(s) {
		if w == "-" {
			out = append(out, w)
			continue
		}
		w = strings.Trim(w, ",.-&")
		if w != "" {
			out = append(out, w)
		}
	}
	return out
}

func capWords(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		r := []rune(p)
		r[0] = unicode.ToUpper(r[0])
		parts[i] = string(r)
	}
	return strings.Join(parts, " ")
}

func titleCase(s string) string {
	parts := strings.Fields(s)
	for i, p := range parts {
		sub := strings.Split(p, "-")
		for j, w := range sub {
			r := []rune(w)
			if len(r) <= 3 {
				continue
			}
			sub[j] = string(unicode.ToUpper(r[0])) + strings.ToLower(string(r[1:]))
		}
		parts[i] = strings.Join(sub, "-")
	}
	return strings.Join(parts, " ")
}
