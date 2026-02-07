// Package cli implements the Junos-style interactive CLI for bpfrx.
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
	"github.com/psviderski/bpfrx/pkg/config"
	"github.com/psviderski/bpfrx/pkg/configstore"
	"github.com/psviderski/bpfrx/pkg/dataplane"
)

// CLI is the interactive command-line interface.
type CLI struct {
	rl       *readline.Instance
	store    *configstore.Store
	dp       *dataplane.Manager
	hostname string
	username string
}

// New creates a new CLI.
func New(store *configstore.Store, dp *dataplane.Manager) *CLI {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	username := os.Getenv("USER")
	if username == "" {
		username = "root"
	}

	return &CLI{
		store:    store,
		dp:       dp,
		hostname: hostname,
		username: username,
	}
}

// Run starts the interactive CLI loop.
func (c *CLI) Run() error {
	var err error
	c.rl, err = readline.NewEx(&readline.Config{
		Prompt:          c.operationalPrompt(),
		HistoryFile:     "/tmp/bpfrx_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return fmt.Errorf("readline init: %w", err)
	}
	defer c.rl.Close()

	fmt.Println("bpfrx firewall - Junos-style eBPF firewall")
	fmt.Println("Type '?' for help")
	fmt.Println()

	for {
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				continue
			}
			if err == io.EOF {
				break
			}
			return err
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if err := c.dispatch(line); err != nil {
			if err == errExit {
				return nil
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
		}
	}
	return nil
}

var errExit = fmt.Errorf("exit")

func (c *CLI) dispatch(line string) error {
	if c.store.InConfigMode() {
		return c.dispatchConfig(line)
	}
	return c.dispatchOperational(line)
}

func (c *CLI) dispatchOperational(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "configure":
		c.store.EnterConfigure()
		c.rl.SetPrompt(c.configPrompt())
		fmt.Println("Entering configuration mode")
		return nil

	case "show":
		return c.handleShow(parts[1:])

	case "quit", "exit":
		return errExit

	case "?", "help":
		c.showOperationalHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}

func (c *CLI) dispatchConfig(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "set":
		if len(parts) < 2 {
			return fmt.Errorf("set: missing path")
		}
		return c.store.SetFromInput(strings.Join(parts[1:], " "))

	case "delete":
		return fmt.Errorf("delete: not yet implemented")

	case "show":
		return c.handleConfigShow(parts[1:])

	case "commit":
		return c.handleCommit(parts[1:])

	case "rollback":
		n := 0
		if len(parts) >= 2 {
			fmt.Sscanf(parts[1], "%d", &n)
		}
		if err := c.store.Rollback(n); err != nil {
			return err
		}
		fmt.Println("configuration rolled back")
		return nil

	case "run":
		if len(parts) < 2 {
			return fmt.Errorf("run: missing command")
		}
		return c.dispatchOperational(strings.Join(parts[1:], " "))

	case "exit", "quit":
		if c.store.IsDirty() {
			fmt.Println("warning: uncommitted changes will be discarded")
		}
		c.store.ExitConfigure()
		c.rl.SetPrompt(c.operationalPrompt())
		fmt.Println("Exiting configuration mode")
		return nil

	case "?", "help":
		c.showConfigHelp()
		return nil

	default:
		return fmt.Errorf("unknown command: %s (in configuration mode)", parts[0])
	}
}

func (c *CLI) handleShow(args []string) error {
	if len(args) == 0 {
		fmt.Println("show: specify what to show")
		fmt.Println("  configuration    Show active configuration")
		fmt.Println("  security         Show security information")
		fmt.Println("  interfaces       Show interface status")
		return nil
	}

	switch args[0] {
	case "configuration":
		fmt.Print(c.store.ShowActive())
		return nil

	case "security":
		return c.handleShowSecurity(args[1:])

	default:
		return fmt.Errorf("unknown show target: %s", args[0])
	}
}

func (c *CLI) handleShowSecurity(args []string) error {
	if len(args) == 0 {
		fmt.Println("show security:")
		fmt.Println("  zones            Show security zones")
		fmt.Println("  policies         Show security policies")
		fmt.Println("  flow session     Show active sessions")
		return nil
	}

	cfg := c.store.ActiveConfig()
	if cfg == nil {
		fmt.Println("no active configuration")
		return nil
	}

	switch args[0] {
	case "zones":
		for name, zone := range cfg.Security.Zones {
			fmt.Printf("Zone: %s\n", name)
			fmt.Printf("  Interfaces: %s\n", strings.Join(zone.Interfaces, ", "))
			if zone.ScreenProfile != "" {
				fmt.Printf("  Screen: %s\n", zone.ScreenProfile)
			}
			fmt.Println()
		}
		return nil

	case "policies":
		for _, zpp := range cfg.Security.Policies {
			fmt.Printf("From zone: %s, To zone: %s\n", zpp.FromZone, zpp.ToZone)
			for _, pol := range zpp.Policies {
				action := "permit"
				switch pol.Action {
				case 1:
					action = "deny"
				case 2:
					action = "reject"
				}
				fmt.Printf("  Policy: %s\n", pol.Name)
				fmt.Printf("    Match: src=%v dst=%v app=%v\n",
					pol.Match.SourceAddresses,
					pol.Match.DestinationAddresses,
					pol.Match.Applications)
				fmt.Printf("    Action: %s\n", action)
			}
			fmt.Println()
		}
		return nil

	case "flow":
		if len(args) >= 2 && args[1] == "session" {
			fmt.Println("Session table: (not yet implemented)")
			return nil
		}
		return fmt.Errorf("unknown show security flow target")

	default:
		return fmt.Errorf("unknown show security target: %s", args[0])
	}
}

func (c *CLI) handleConfigShow(args []string) error {
	// Check for pipe commands
	line := strings.Join(args, " ")

	if strings.Contains(line, "| display set") {
		fmt.Print(c.store.ShowCandidateSet())
		return nil
	}

	fmt.Print(c.store.ShowCandidate())
	return nil
}

func (c *CLI) handleCommit(args []string) error {
	if len(args) > 0 && args[0] == "check" {
		_, err := c.store.CommitCheck()
		if err != nil {
			return fmt.Errorf("commit check failed: %w", err)
		}
		fmt.Println("configuration check succeeds")
		return nil
	}

	compiled, err := c.store.Commit()
	if err != nil {
		return fmt.Errorf("commit failed: %w", err)
	}

	// Apply to dataplane
	if c.dp != nil {
		if err := c.applyToDataplane(compiled); err != nil {
			fmt.Fprintf(os.Stderr, "warning: dataplane apply failed: %v\n", err)
		}
	}

	fmt.Println("commit complete")
	return nil
}

func (c *CLI) applyToDataplane(cfg *config.Config) error {
	if c.dp == nil {
		return nil
	}

	// Apply zone configuration
	for _, zone := range cfg.Security.Zones {
		for _, ifaceName := range zone.Interfaces {
			// Resolve interface name to ifindex via netlink
			// For now, this is a placeholder.
			_ = ifaceName
		}
	}

	return nil
}

func (c *CLI) operationalPrompt() string {
	return fmt.Sprintf("%s@%s> ", c.username, c.hostname)
}

func (c *CLI) configPrompt() string {
	return fmt.Sprintf("[edit]\n%s@%s# ", c.username, c.hostname)
}

func (c *CLI) showOperationalHelp() {
	fmt.Println("Operational mode commands:")
	fmt.Println("  configure          Enter configuration mode")
	fmt.Println("  show configuration Show running configuration")
	fmt.Println("  show security      Show security information")
	fmt.Println("  quit               Exit CLI")
}

func (c *CLI) showConfigHelp() {
	fmt.Println("Configuration mode commands:")
	fmt.Println("  set <path>         Set a configuration value")
	fmt.Println("  delete <path>      Delete a configuration element")
	fmt.Println("  show               Show candidate configuration")
	fmt.Println("  show | display set Show as flat set commands")
	fmt.Println("  commit             Validate and apply configuration")
	fmt.Println("  commit check       Validate without applying")
	fmt.Println("  rollback [n]       Revert to previous configuration")
	fmt.Println("  run <cmd>          Run operational command")
	fmt.Println("  exit               Exit configuration mode")
}
