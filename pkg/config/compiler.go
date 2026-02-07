package config

import (
	"fmt"
	"strconv"
)

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications: make(map[string]*Application),
		},
	}

	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return nil, fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
				return nil, fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return nil, fmt.Errorf("applications: %w", err)
			}
		}
	}

	return cfg, nil
}

func compileSecurity(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		switch child.Name() {
		case "zones":
			if err := compileZones(child, sec); err != nil {
				return fmt.Errorf("zones: %w", err)
			}
		case "policies":
			if err := compilePolicies(child, sec); err != nil {
				return fmt.Errorf("policies: %w", err)
			}
		case "screen":
			if err := compileScreen(child, sec); err != nil {
				return fmt.Errorf("screen: %w", err)
			}
		case "address-book":
			if err := compileAddressBook(child, sec); err != nil {
				return fmt.Errorf("address-book: %w", err)
			}
		}
	}
	return nil
}

func compileZones(node *Node, sec *SecurityConfig) error {
	for _, child := range node.FindChildren("security-zone") {
		if len(child.Keys) < 2 {
			return fmt.Errorf("security-zone missing name at line %d", child.Line)
		}
		zoneName := child.Keys[1]
		zone := &ZoneConfig{Name: zoneName}

		for _, prop := range child.Children {
			switch prop.Name() {
			case "interfaces":
				for _, iface := range prop.Children {
					zone.Interfaces = append(zone.Interfaces, iface.Name())
				}
			case "screen":
				// "screen untrust-screen;" or "screen ids-option name;"
				if len(prop.Keys) >= 2 {
					zone.ScreenProfile = prop.Keys[1]
				}
			case "host-inbound-traffic":
				zone.HostInboundTraffic = &HostInboundTraffic{}
				for _, hit := range prop.Children {
					switch hit.Name() {
					case "system-services":
						for _, svc := range hit.Children {
							zone.HostInboundTraffic.SystemServices = append(
								zone.HostInboundTraffic.SystemServices, svc.Name())
						}
					case "protocols":
						for _, proto := range hit.Children {
							zone.HostInboundTraffic.Protocols = append(
								zone.HostInboundTraffic.Protocols, proto.Name())
						}
					}
				}
			}
		}

		sec.Zones[zoneName] = zone
	}
	return nil
}

func compilePolicies(node *Node, sec *SecurityConfig) error {
	for _, child := range node.Children {
		if child.Name() == "default-policy" {
			continue
		}
		// "from-zone trust to-zone untrust { ... }"
		if child.Name() == "from-zone" && len(child.Keys) >= 4 {
			fromZone := child.Keys[1]
			toZone := child.Keys[3] // "to-zone" is at index 2
			zpp := &ZonePairPolicies{
				FromZone: fromZone,
				ToZone:   toZone,
			}

			for _, policyNode := range child.FindChildren("policy") {
				if len(policyNode.Keys) < 2 {
					continue
				}
				pol := &Policy{Name: policyNode.Keys[1]}

				matchNode := policyNode.FindChild("match")
				if matchNode != nil {
					for _, m := range matchNode.Children {
						switch m.Name() {
						case "source-address":
							if len(m.Keys) >= 2 {
								pol.Match.SourceAddresses = append(pol.Match.SourceAddresses, m.Keys[1])
							}
						case "destination-address":
							if len(m.Keys) >= 2 {
								pol.Match.DestinationAddresses = append(pol.Match.DestinationAddresses, m.Keys[1])
							}
						case "application":
							if len(m.Keys) >= 2 {
								pol.Match.Applications = append(pol.Match.Applications, m.Keys[1])
							}
						}
					}
				}

				thenNode := policyNode.FindChild("then")
				if thenNode != nil {
					for _, t := range thenNode.Children {
						switch t.Name() {
						case "permit":
							pol.Action = PolicyPermit
						case "deny":
							pol.Action = PolicyDeny
						case "reject":
							pol.Action = PolicyReject
						case "log":
							pol.Log = &PolicyLog{}
							for _, logOpt := range t.Children {
								switch logOpt.Name() {
								case "session-init":
									pol.Log.SessionInit = true
								case "session-close":
									pol.Log.SessionClose = true
								}
							}
						case "count":
							pol.Count = true
						}
					}
				}

				zpp.Policies = append(zpp.Policies, pol)
			}

			sec.Policies = append(sec.Policies, zpp)
		}
	}
	return nil
}

func compileScreen(node *Node, sec *SecurityConfig) error {
	for _, child := range node.FindChildren("ids-option") {
		if len(child.Keys) < 2 {
			continue
		}
		profile := &ScreenProfile{Name: child.Keys[1]}

		icmpNode := child.FindChild("icmp")
		if icmpNode != nil {
			for _, opt := range icmpNode.Children {
				switch opt.Name() {
				case "ping-death":
					profile.ICMP.PingDeath = true
				case "flood":
					if len(opt.Keys) >= 3 {
						if v, err := strconv.Atoi(opt.Keys[2]); err == nil {
							profile.ICMP.FloodThreshold = v
						}
					}
				}
			}
		}

		ipNode := child.FindChild("ip")
		if ipNode != nil {
			for _, opt := range ipNode.Children {
				switch opt.Name() {
				case "source-route-option":
					profile.IP.SourceRouteOption = true
				case "tear-drop":
					profile.IP.TearDrop = true
				}
			}
		}

		tcpNode := child.FindChild("tcp")
		if tcpNode != nil {
			for _, opt := range tcpNode.Children {
				switch opt.Name() {
				case "land":
					profile.TCP.Land = true
				case "winnuke":
					profile.TCP.WinNuke = true
				case "syn-frag":
					profile.TCP.SynFrag = true
				case "syn-flood":
					sf := &SynFloodConfig{}
					for _, sfOpt := range opt.Children {
						if len(sfOpt.Keys) >= 2 {
							val, _ := strconv.Atoi(sfOpt.Keys[1])
							switch sfOpt.Name() {
							case "alarm-threshold":
								sf.AlarmThreshold = val
							case "attack-threshold":
								sf.AttackThreshold = val
							case "source-threshold":
								sf.SourceThreshold = val
							case "timeout":
								sf.Timeout = val
							}
						}
					}
					profile.TCP.SynFlood = sf
				}
			}
		}

		sec.Screen[profile.Name] = profile
	}
	return nil
}

func compileAddressBook(node *Node, sec *SecurityConfig) error {
	globalNode := node.FindChild("global")
	if globalNode == nil {
		return nil
	}

	ab := &AddressBook{
		Addresses:   make(map[string]*Address),
		AddressSets: make(map[string]*AddressSet),
	}

	for _, child := range globalNode.Children {
		switch child.Name() {
		case "address":
			if len(child.Keys) >= 3 {
				addr := &Address{
					Name:  child.Keys[1],
					Value: child.Keys[2],
				}
				ab.Addresses[addr.Name] = addr
			}
		case "address-set":
			if len(child.Keys) >= 2 {
				as := &AddressSet{Name: child.Keys[1]}
				for _, member := range child.Children {
					if member.Name() == "address" && len(member.Keys) >= 2 {
						as.Addresses = append(as.Addresses, member.Keys[1])
					}
				}
				ab.AddressSets[as.Name] = as
			}
		}
	}

	sec.AddressBook = ab
	return nil
}

func compileInterfaces(node *Node, ifaces *InterfacesConfig) error {
	for _, child := range node.Children {
		if child.IsLeaf {
			continue
		}
		ifName := child.Name()
		ifc := &InterfaceConfig{
			Name:  ifName,
			Units: make(map[int]*InterfaceUnit),
		}

		for _, unitNode := range child.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			unitNum, err := strconv.Atoi(unitNode.Keys[1])
			if err != nil {
				continue
			}
			unit := &InterfaceUnit{Number: unitNum}

			familyNode := unitNode.FindChild("family")
			if familyNode != nil {
				inetNode := familyNode.FindChild("inet")
				if inetNode != nil {
					for _, addrNode := range inetNode.FindChildren("address") {
						if len(addrNode.Keys) >= 2 {
							unit.Addresses = append(unit.Addresses, addrNode.Keys[1])
						}
					}
				}
			}

			ifc.Units[unitNum] = unit
		}

		ifaces.Interfaces[ifName] = ifc
	}
	return nil
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, child := range node.FindChildren("application") {
		if len(child.Keys) < 2 {
			continue
		}
		app := &Application{Name: child.Keys[1]}

		for _, prop := range child.Children {
			switch prop.Name() {
			case "protocol":
				if len(prop.Keys) >= 2 {
					app.Protocol = prop.Keys[1]
				}
			case "destination-port":
				if len(prop.Keys) >= 2 {
					app.DestinationPort = prop.Keys[1]
				}
			}
		}

		apps.Applications[app.Name] = app
	}
	return nil
}
