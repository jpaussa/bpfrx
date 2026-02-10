// Package feeds implements dynamic address feed fetching and management.
package feeds

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// Manager manages dynamic address feed servers and their periodic updates.
type Manager struct {
	mu      sync.RWMutex
	feeds   map[string]*feedState // keyed by feed-server name
	client  *http.Client
	onUpdate func() // callback when feeds are updated
}

type feedState struct {
	cfg      *config.FeedServer
	prefixes []string // currently fetched CIDRs
	lastFetch time.Time
	cancel   context.CancelFunc
}

// New creates a new feed manager.
// onUpdate is called whenever a feed refresh produces new prefixes.
func New(onUpdate func()) *Manager {
	return &Manager{
		feeds: make(map[string]*feedState),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		onUpdate: onUpdate,
	}
}

// Apply configures feeds from the given dynamic address config.
// Starts background refresh goroutines for each feed server.
func (m *Manager) Apply(ctx context.Context, daCfg *config.DynamicAddressConfig) {
	m.StopAll()

	if daCfg == nil || len(daCfg.FeedServers) == 0 {
		return
	}

	m.mu.Lock()
	for name, fsCfg := range daCfg.FeedServers {
		if fsCfg.URL == "" {
			continue
		}
		feedCtx, cancel := context.WithCancel(ctx)
		fs := &feedState{
			cfg:    fsCfg,
			cancel: cancel,
		}
		m.feeds[name] = fs

		interval := time.Duration(fsCfg.UpdateInterval) * time.Second
		if interval <= 0 {
			interval = time.Hour
		}

		go m.refreshLoop(feedCtx, fs, interval)
		slog.Info("dynamic address feed started",
			"name", name, "url", fsCfg.URL, "interval", interval)
	}
	m.mu.Unlock()
}

// StopAll cancels all running feed refresh goroutines.
func (m *Manager) StopAll() {
	m.mu.Lock()
	for _, fs := range m.feeds {
		if fs.cancel != nil {
			fs.cancel()
		}
	}
	m.feeds = make(map[string]*feedState)
	m.mu.Unlock()
}

// GetPrefixes returns the current prefixes for a named feed server.
func (m *Manager) GetPrefixes(name string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if fs, ok := m.feeds[name]; ok {
		return append([]string(nil), fs.prefixes...)
	}
	return nil
}

// AllFeeds returns a snapshot of all feed states for display.
func (m *Manager) AllFeeds() map[string]FeedInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]FeedInfo, len(m.feeds))
	for name, fs := range m.feeds {
		result[name] = FeedInfo{
			URL:       fs.cfg.URL,
			Prefixes:  len(fs.prefixes),
			LastFetch: fs.lastFetch,
		}
	}
	return result
}

// FeedInfo holds display information about a feed.
type FeedInfo struct {
	URL       string
	Prefixes  int
	LastFetch time.Time
}

func (m *Manager) refreshLoop(ctx context.Context, fs *feedState, interval time.Duration) {
	// Initial fetch
	m.fetchFeed(ctx, fs)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.fetchFeed(ctx, fs)
		}
	}
}

func (m *Manager) fetchFeed(ctx context.Context, fs *feedState) {
	req, err := http.NewRequestWithContext(ctx, "GET", fs.cfg.URL, nil)
	if err != nil {
		slog.Warn("dynamic-address: invalid URL", "name", fs.cfg.Name, "err", err)
		return
	}

	resp, err := m.client.Do(req)
	if err != nil {
		slog.Warn("dynamic-address: fetch failed", "name", fs.cfg.Name, "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("dynamic-address: unexpected status",
			"name", fs.cfg.Name, "status", resp.StatusCode)
		return
	}

	var prefixes []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		// Validate as CIDR or plain IP
		if _, _, err := net.ParseCIDR(line); err == nil {
			prefixes = append(prefixes, line)
		} else if ip := net.ParseIP(line); ip != nil {
			if ip.To4() != nil {
				prefixes = append(prefixes, fmt.Sprintf("%s/32", line))
			} else {
				prefixes = append(prefixes, fmt.Sprintf("%s/128", line))
			}
		}
	}

	m.mu.Lock()
	oldCount := len(fs.prefixes)
	fs.prefixes = prefixes
	fs.lastFetch = time.Now()
	m.mu.Unlock()

	slog.Info("dynamic-address: feed updated",
		"name", fs.cfg.Name, "prefixes", len(prefixes), "previous", oldCount)

	if m.onUpdate != nil && len(prefixes) != oldCount {
		m.onUpdate()
	}
}
