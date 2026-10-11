package oui

import (
	"strings"
	"testing"
)

func TestLookupKnown(t *testing.T) {
	if got := Lookup("B8:27:EB:00:00:00"); !strings.Contains(got, "Raspberry") {
		t.Errorf("raspberry: got %q", got)
	}
	if got := Lookup("F0:18:98:12:34:56"); got != "Apple" {
		t.Errorf("apple: got %q", got)
	}
}

func TestLookupFormats(t *testing.T) {
	if got := Lookup("f0-18-98-12-34-56"); got != "Apple" {
		t.Errorf("lowercase dash: got %q", got)
	}
	if got := Lookup("f0:18:98"); got != "Apple" {
		t.Errorf("prefix only: got %q", got)
	}
}

func TestLookupInvalid(t *testing.T) {
	for _, s := range []string{"", "zz:zz:zz:00:00:00", "F0189812", "F0.18.98.12.34.56", "F0:18"} {
		if got := Lookup(s); got != "" {
			t.Errorf("Lookup(%q) = %q, want empty", s, got)
		}
	}
}

func TestLookupLocallyAdministered(t *testing.T) {
	for _, s := range []string{"02:42:AC:11:00:02", "FE:EE:E6:00:34:B4"} {
		if got := Lookup(s); got != "" {
			t.Errorf("Lookup(%q) = %q, want empty", s, got)
		}
	}
}

func TestTableSize(t *testing.T) {
	if n := size(); n <= 30000 {
		t.Errorf("table has %d entries, want > 30000", n)
	}
}
