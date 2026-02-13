package dhcprelay

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestAddOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}

	// Parse sub-option: type(1) + length + value
	if len(opt) < 2 {
		t.Fatalf("Option 82 too short: %d bytes", len(opt))
	}
	if opt[0] != suboption1CircuitID {
		t.Errorf("sub-option type: got %d, want %d", opt[0], suboption1CircuitID)
	}
	if opt[1] != byte(len("trust0")) {
		t.Errorf("sub-option length: got %d, want %d", opt[1], len("trust0"))
	}
	circuitID := string(opt[2:])
	if circuitID != "trust0" {
		t.Errorf("circuit-id: got %q, want %q", circuitID, "trust0")
	}
}

func TestStripOption82(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	if pkt.Options.Get(option82) == nil {
		t.Fatal("Option 82 should be present before strip")
	}

	stripOption82(pkt)
	if pkt.Options.Get(option82) != nil {
		t.Error("Option 82 should be removed after strip")
	}
}

func TestAddOption82_Replaces(t *testing.T) {
	pkt, err := dhcpv4.New()
	if err != nil {
		t.Fatal(err)
	}

	addOption82(pkt, "trust0")
	addOption82(pkt, "dmz0")

	opt := pkt.Options.Get(option82)
	if opt == nil {
		t.Fatal("Option 82 not found")
	}
	circuitID := string(opt[2:])
	if circuitID != "dmz0" {
		t.Errorf("circuit-id should be replaced: got %q, want %q", circuitID, "dmz0")
	}
}

func TestInterfaceIPv4_Loopback(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no loopback interface")
	}
	ip, err := interfaceIPv4(lo)
	if err == nil {
		t.Errorf("expected error for loopback, got IP %s", ip)
	}
}
