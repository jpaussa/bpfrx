package dhcp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
)

func TestExtractDelegatedPrefixes(t *testing.T) {
	now := time.Now()

	t.Run("single prefix", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		iapd := &dhcpv6.OptIAPD{
			IaId: [4]byte{0, 0, 0, 1},
		}
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2001:db8:1000::"),
				Mask: net.CIDRMask(48, 128),
			},
		})
		msg.AddOption(iapd)

		pds := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 1 {
			t.Fatalf("got %d prefixes, want 1", len(pds))
		}
		want := netip.MustParsePrefix("2001:db8:1000::/48")
		if pds[0].Prefix != want {
			t.Errorf("prefix = %s, want %s", pds[0].Prefix, want)
		}
		if pds[0].PreferredLifetime != 3600*time.Second {
			t.Errorf("preferred = %s, want 1h0m0s", pds[0].PreferredLifetime)
		}
		if pds[0].ValidLifetime != 7200*time.Second {
			t.Errorf("valid = %s, want 2h0m0s", pds[0].ValidLifetime)
		}
		if pds[0].Interface != "wan0" {
			t.Errorf("interface = %q, want wan0", pds[0].Interface)
		}
	})

	t.Run("no IA_PD", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		pds := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 0 {
			t.Errorf("got %d prefixes, want 0", len(pds))
		}
	})

	t.Run("multiple prefixes", func(t *testing.T) {
		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeReply

		iapd := &dhcpv6.OptIAPD{
			IaId: [4]byte{0, 0, 0, 1},
		}
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 3600 * time.Second,
			ValidLifetime:     7200 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2001:db8:1000::"),
				Mask: net.CIDRMask(48, 128),
			},
		})
		iapd.Options.Add(&dhcpv6.OptIAPrefix{
			PreferredLifetime: 1800 * time.Second,
			ValidLifetime:     3600 * time.Second,
			Prefix: &net.IPNet{
				IP:   net.ParseIP("2001:db8:2000::"),
				Mask: net.CIDRMask(56, 128),
			},
		})
		msg.AddOption(iapd)

		pds := extractDelegatedPrefixes(msg, "wan0", now)
		if len(pds) != 2 {
			t.Fatalf("got %d prefixes, want 2", len(pds))
		}
		if pds[1].Prefix != netip.MustParsePrefix("2001:db8:2000::/56") {
			t.Errorf("second prefix = %s, want 2001:db8:2000::/56", pds[1].Prefix)
		}
	})
}

func TestDelegatedPrefixes(t *testing.T) {
	m := &Manager{
		delegatedPDs: map[string][]DelegatedPrefix{
			"wan0": {
				{Interface: "wan0", Prefix: netip.MustParsePrefix("2001:db8::/48")},
			},
			"wan1": {
				{Interface: "wan1", Prefix: netip.MustParsePrefix("2001:db8:1::/48")},
				{Interface: "wan1", Prefix: netip.MustParsePrefix("2001:db8:2::/56")},
			},
		},
	}

	pds := m.DelegatedPrefixes()
	if len(pds) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(pds))
	}
}

func TestBuildDHCPv6Modifiers(t *testing.T) {
	m := &Manager{
		duids:     make(map[string]dhcpv6.DUID),
		duidTypes: make(map[string]string),
		v6opts:    make(map[string]*DHCPv6Options),
	}

	t.Run("nil opts", func(t *testing.T) {
		mods := m.buildDHCPv6Modifiers("eth0", nil)
		if len(mods) != 0 {
			t.Errorf("got %d modifiers, want 0", len(mods))
		}
	})

	t.Run("ia-pd with hint", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:   []string{"ia-pd"},
			PDPrefLen: 56,
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		found := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				found = true
			}
		}
		if !found {
			t.Error("IA_PD option not found")
		}
	})

	t.Run("ia-pd without hint", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:   []string{"ia-pd"},
			PDPrefLen: 0,
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		found := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				found = true
			}
		}
		if !found {
			t.Error("IA_PD option should be present even without hint")
		}
	})

	t.Run("requested options", func(t *testing.T) {
		opts := &DHCPv6Options{
			ReqOptions: []string{"dns-server", "domain-name"},
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		oro := msg.Options.RequestedOptions()
		hasDNS, hasDomain := false, false
		for _, code := range oro {
			if code == dhcpv6.OptionDNSRecursiveNameServer {
				hasDNS = true
			}
			if code == dhcpv6.OptionDomainSearchList {
				hasDomain = true
			}
		}
		if !hasDNS {
			t.Error("DNS option not in ORO")
		}
		if !hasDomain {
			t.Error("Domain option not in ORO")
		}
	})

	t.Run("both ia types with req opts", func(t *testing.T) {
		opts := &DHCPv6Options{
			IATypes:    []string{"ia-na", "ia-pd"},
			PDPrefLen:  60,
			ReqOptions: []string{"dns-server"},
		}
		mods := m.buildDHCPv6Modifiers("eth0", opts)

		msg, err := dhcpv6.NewMessage()
		if err != nil {
			t.Fatal(err)
		}
		msg.MessageType = dhcpv6.MessageTypeSolicit
		for _, mod := range mods {
			mod(msg)
		}

		hasIAPD := false
		for _, opt := range msg.Options.Options {
			if _, ok := opt.(*dhcpv6.OptIAPD); ok {
				hasIAPD = true
			}
		}
		if !hasIAPD {
			t.Error("IA_PD not found when both ia types requested")
		}
	})
}

func TestDHCPv6OptionsSetGet(t *testing.T) {
	m := &Manager{
		v6opts: make(map[string]*DHCPv6Options),
	}

	opts := &DHCPv6Options{
		IATypes:    []string{"ia-na", "ia-pd"},
		PDPrefLen:  60,
		PDSubLen:   64,
		ReqOptions: []string{"dns-server"},
		RAIface:    "trust0",
	}

	m.SetDHCPv6Options("wan0", opts)

	m.mu.Lock()
	got := m.v6opts["wan0"]
	m.mu.Unlock()

	if got == nil {
		t.Fatal("v6opts not set")
	}
	if len(got.IATypes) != 2 {
		t.Errorf("IATypes = %v, want [ia-na ia-pd]", got.IATypes)
	}
	if got.PDPrefLen != 60 {
		t.Errorf("PDPrefLen = %d, want 60", got.PDPrefLen)
	}
	if got.RAIface != "trust0" {
		t.Errorf("RAIface = %q, want trust0", got.RAIface)
	}
}
