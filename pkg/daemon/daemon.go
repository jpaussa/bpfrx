// Package daemon implements the bpfrx daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/psviderski/bpfrx/pkg/cli"
	"github.com/psviderski/bpfrx/pkg/configstore"
	"github.com/psviderski/bpfrx/pkg/conntrack"
	"github.com/psviderski/bpfrx/pkg/dataplane"
	"github.com/psviderski/bpfrx/pkg/logging"
)

// Options configures the daemon.
type Options struct {
	ConfigFile string
	NoDataplane bool // set to true to run without eBPF (config-only mode)
}

// Daemon is the main bpfrx daemon.
type Daemon struct {
	opts  Options
	store *configstore.Store
	dp    *dataplane.Manager
}

// New creates a new Daemon.
func New(opts Options) *Daemon {
	if opts.ConfigFile == "" {
		opts.ConfigFile = "/etc/bpfrx/bpfrx.conf"
	}

	return &Daemon{
		opts:  opts,
		store: configstore.New(opts.ConfigFile),
	}
}

// Run starts the daemon and blocks until shutdown.
func (d *Daemon) Run(ctx context.Context) error {
	slog.Info("starting bpfrx daemon",
		"config", d.opts.ConfigFile,
		"pid", os.Getpid())

	// Load persisted configuration
	if err := d.store.Load(); err != nil {
		slog.Warn("failed to load config, starting with empty config",
			"err", err)
	} else {
		slog.Info("configuration loaded", "file", d.opts.ConfigFile)
	}

	// Load eBPF programs (unless in config-only mode)
	if !d.opts.NoDataplane {
		d.dp = dataplane.New()
		if err := d.dp.Load(); err != nil {
			slog.Warn("failed to load eBPF programs, running in config-only mode",
				"err", err)
			d.dp = nil
		} else {
			defer d.dp.Close()
			// Apply current config to dataplane
			if cfg := d.store.ActiveConfig(); cfg != nil {
				slog.Info("applying active configuration to dataplane")
				if _, err := d.dp.Compile(cfg); err != nil {
					slog.Warn("failed to apply active config", "err", err)
				}
			}
		}
	}

	// Handle signals for clean shutdown
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Start background services if dataplane is loaded
	if d.dp != nil {
		gc := conntrack.NewGC(d.dp, 10*time.Second)
		go gc.Run(ctx)

		eventsMap := d.dp.Map("events")
		if eventsMap != nil {
			er := logging.NewEventReader(eventsMap)
			go er.Run(ctx)
		}
	}

	// Start CLI shell
	shell := cli.New(d.store, d.dp)

	// Run CLI in a goroutine so we can still handle signals
	errCh := make(chan error, 1)
	go func() {
		errCh <- shell.Run()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("CLI: %w", err)
		}
		return nil
	case <-ctx.Done():
		slog.Info("shutting down")
		return nil
	}
}
