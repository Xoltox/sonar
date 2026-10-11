package target

import (
	"strings"
	"testing"
)

func TestResolveSpecs(t *testing.T) {
	hosts, _, desc, err := Resolve([]string{"10.0.0.0/30", "10.0.0.2-5"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 5 {
		t.Fatalf("got %d hosts, want 5", len(hosts))
	}
	if len(desc) != 2 || desc[0] != "10.0.0.0/30" {
		t.Fatalf("desc = %v", desc)
	}
}

func TestResolveCap(t *testing.T) {
	_, _, _, err := Resolve([]string{"10.0.0.0/15"}, false)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want cap error, got %v", err)
	}
	hosts, _, _, err := Resolve([]string{"10.0.0.0/15"}, true)
	if err != nil || len(hosts) != 131070 {
		t.Fatalf("force: %d hosts, err %v", len(hosts), err)
	}
}

func TestResolveBadSpec(t *testing.T) {
	if _, _, _, err := Resolve([]string{"nope"}, false); err == nil {
		t.Fatal("want error")
	}
}

func TestResolveEmptyDescribesLocals(t *testing.T) {
	hosts, locals, desc, err := Resolve(nil, false)
	if err != nil {
		t.Skipf("no usable local subnets: %v", err)
	}
	if len(desc) != len(locals) || len(hosts) == 0 {
		t.Fatalf("desc=%v locals=%d hosts=%d", desc, len(locals), len(hosts))
	}
}
