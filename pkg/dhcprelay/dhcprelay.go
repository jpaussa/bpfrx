// Package dhcprelay implements DHCP relay agent functionality.
package dhcprelay

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/psaab/bpfrx/pkg/config"
	"github.com/vishvananda/netlink"
)

// Agent manages DHCP relay processes for configured interfaces.
type Agent struct {
	mu           sync.Mutex
	relays       map[string]*relay        // keyed by interface name
	serverGroups map[string][]net.IP      // keyed by group name
	nlHandle     *netlink.Handle
	ctx          context.Context
	cancel       context.CancelFunc
}

// relay represents a single relay instance on an interface.
type relay struct {
	iface       string
	serverGroup string
	family      int // unix.AF_INET or unix.AF_INET6
	cancel      context.CancelFunc
	done        chan struct{}
}

// New creates a new DHCP relay agent.
func New() (*Agent, error) {
	nlHandle, err := netlink.NewHandle()
	if err != nil {
		return nil, fmt.Errorf("netlink handle: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Agent{
		relays:       make(map[string]*relay),
		serverGroups: make(map[string][]net.IP),
		nlHandle:     nlHandle,
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// Configure applies DHCP relay configuration from the active config.
func (a *Agent) Configure(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Build server group map
	newServerGroups := make(map[string][]net.IP)
	if cfg.ForwardingOptions.DHCPRelay != nil {
		for name, group := range cfg.ForwardingOptions.DHCPRelay.ServerGroups {
			var ips []net.IP
			for _, serverStr := range group.Servers {
				ip := net.ParseIP(serverStr)
				if ip == nil {
					slog.Warn("invalid DHCP relay server IP", "server", serverStr, "group", name)
					continue
				}
				ips = append(ips, ip)
			}
			newServerGroups[name] = ips
		}
	}
	a.serverGroups = newServerGroups

	// Track which relays should be active
	activeRelays := make(map[string]bool)

	// Configure relay for each interface unit
	for ifaceName, iface := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range iface.Units {
			// Construct logical interface name
			logicalName := ifaceName
			if unitNum != 0 {
				logicalName = fmt.Sprintf("%s.%d", ifaceName, unitNum)
			}

			// DHCPv4 relay
			if unit.DHCPRelay != nil {
				key := fmt.Sprintf("%s:inet", logicalName)
				activeRelays[key] = true

				// Validate server group exists
				if _, ok := a.serverGroups[unit.DHCPRelay.ServerGroup]; !ok {
					slog.Warn("DHCP relay references non-existent server-group",
						"interface", logicalName,
						"server-group", unit.DHCPRelay.ServerGroup)
					continue
				}

				// Start relay if not already running
				if _, exists := a.relays[key]; !exists {
					if err := a.startRelay(logicalName, unit.DHCPRelay.ServerGroup, 2); err != nil { // AF_INET=2
						slog.Warn("failed to start DHCPv4 relay",
							"interface", logicalName,
							"err", err)
					}
				}
			}

			// DHCPv6 relay
			if unit.DHCPRelayV6 != nil {
				key := fmt.Sprintf("%s:inet6", logicalName)
				activeRelays[key] = true

				// Validate server group exists
				if _, ok := a.serverGroups[unit.DHCPRelayV6.ServerGroup]; !ok {
					slog.Warn("DHCPv6 relay references non-existent server-group",
						"interface", logicalName,
						"server-group", unit.DHCPRelayV6.ServerGroup)
					continue
				}

				// Start relay if not already running
				if _, exists := a.relays[key]; !exists {
					if err := a.startRelay(logicalName, unit.DHCPRelayV6.ServerGroup, 10); err != nil { // AF_INET6=10
						slog.Warn("failed to start DHCPv6 relay",
							"interface", logicalName,
							"err", err)
					}
				}
			}
		}
	}

	// Stop relays that are no longer configured
	for key, r := range a.relays {
		if !activeRelays[key] {
			slog.Info("stopping DHCP relay", "interface", r.iface, "family", r.family)
			r.cancel()
			<-r.done
			delete(a.relays, key)
		}
	}

	return nil
}

// startRelay starts a DHCP relay goroutine for the given interface.
func (a *Agent) startRelay(ifaceName, serverGroup string, family int) error {
	slog.Info("starting DHCP relay",
		"interface", ifaceName,
		"server-group", serverGroup,
		"family", family)

	ctx, cancel := context.WithCancel(a.ctx)
	r := &relay{
		iface:       ifaceName,
		serverGroup: serverGroup,
		family:      family,
		cancel:      cancel,
		done:        make(chan struct{}),
	}

	key := fmt.Sprintf("%s:inet", ifaceName)
	if family == 10 {
		key = fmt.Sprintf("%s:inet6", ifaceName)
	}

	a.relays[key] = r

	// Start relay goroutine
	go func() {
		defer close(r.done)
		if err := a.runRelay(ctx, r); err != nil {
			slog.Warn("DHCP relay stopped with error",
				"interface", ifaceName,
				"family", family,
				"err", err)
		}
	}()

	return nil
}

// runRelay is the main relay loop (stub implementation).
// TODO: Implement actual DHCP packet relay logic.
func (a *Agent) runRelay(ctx context.Context, r *relay) error {
	// TODO: Implement DHCPv4/DHCPv6 relay logic
	// For now, just wait for context cancellation
	slog.Info("DHCP relay started (stub implementation)",
		"interface", r.iface,
		"server-group", r.serverGroup,
		"family", r.family)

	<-ctx.Done()
	return nil
}

// StopAll stops all running DHCP relay instances.
func (a *Agent) StopAll() {
	a.mu.Lock()
	defer a.mu.Unlock()

	slog.Info("stopping all DHCP relay instances", "count", len(a.relays))

	a.cancel() // Cancel the root context

	// Wait for all relays to finish
	for key, r := range a.relays {
		<-r.done
		delete(a.relays, key)
	}

	if a.nlHandle != nil {
		a.nlHandle.Close()
	}
}

// Status returns the current status of all relay instances.
// TODO: Add statistics tracking (packets relayed, errors, etc.)
func (a *Agent) Status() map[string]interface{} {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := make(map[string]interface{})
	status["relay_count"] = len(a.relays)
	status["server_groups"] = len(a.serverGroups)

	return status
}
