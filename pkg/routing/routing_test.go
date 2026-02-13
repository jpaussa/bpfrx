package routing

import (
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestResolveRibTable(t *testing.T) {
	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	tests := []struct {
		ribName string
		want    int
	}{
		{"inet.0", 254},
		{"inet6.0", 254},
		{"dmz-vr.inet.0", 101},
		{"dmz-vr.inet6.0", 101},
		{"tunnel-vr.inet.0", 100},
		{"unknown-vr.inet.0", 0},
		{"garbage", 0},
	}

	for _, tt := range tests {
		got := resolveRibTable(tt.ribName, tableIDs)
		if got != tt.want {
			t.Errorf("resolveRibTable(%q) = %d, want %d", tt.ribName, got, tt.want)
		}
	}
}

func TestRibGroupNeedsLeak(t *testing.T) {
	// Verify that the rib-group logic correctly identifies when leaking is needed.
	// We can't test actual ip rule creation without netlink, but we can test
	// the resolveRibTable helper and the logic structure.

	ribGroups := map[string]*config.RibGroup{
		"dmz-leak": {
			Name:       "dmz-leak",
			ImportRibs: []string{"dmz-vr.inet.0", "inet.0"},
		},
		"self-only": {
			Name:       "self-only",
			ImportRibs: []string{"tunnel-vr.inet.0"},
		},
	}

	instances := []*config.RoutingInstanceConfig{
		{Name: "tunnel-vr", TableID: 100, InterfaceRoutesRibGroup: "self-only"},
		{Name: "dmz-vr", TableID: 101, InterfaceRoutesRibGroup: "dmz-leak"},
	}

	tableIDs := map[string]int{
		"tunnel-vr": 100,
		"dmz-vr":    101,
	}

	// dmz-leak should need leaking (dmz-vr.inet.0=101, inet.0=254 → different tables)
	rg := ribGroups["dmz-leak"]
	inst := instances[1] // dmz-vr
	needsLeak := false
	for _, ribName := range rg.ImportRibs {
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
			needsLeak = true
			break
		}
	}
	if !needsLeak {
		t.Error("dmz-leak should need leaking")
	}

	// self-only should NOT need leaking (only tunnel-vr.inet.0=100, same as instance)
	rg = ribGroups["self-only"]
	inst = instances[0] // tunnel-vr
	needsLeak = false
	for _, ribName := range rg.ImportRibs {
		if resolveRibTable(ribName, tableIDs) != inst.TableID {
			needsLeak = true
			break
		}
	}
	if needsLeak {
		t.Error("self-only should NOT need leaking")
	}
}
