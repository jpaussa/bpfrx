package dataplane

import (
	"net/netip"
	"sync"
	"time"
)

// PersistentNATBinding holds a NAT port mapping that survives session GC.
type PersistentNATBinding struct {
	SrcIP    netip.Addr
	SrcPort  uint16
	NatIP    netip.Addr
	NatPort  uint16
	PoolName string
	LastSeen time.Time
	Timeout  time.Duration
}

type persistentNATKey struct {
	SrcIP   netip.Addr
	SrcPort uint16
	Pool    string
}

// PersistentNATTable stores NAT bindings that persist after session close.
type PersistentNATTable struct {
	mu       sync.RWMutex
	bindings map[persistentNATKey]*PersistentNATBinding
}

// NewPersistentNATTable creates a new persistent NAT table.
func NewPersistentNATTable() *PersistentNATTable {
	return &PersistentNATTable{
		bindings: make(map[persistentNATKey]*PersistentNATBinding),
	}
}

// Lookup finds an existing persistent binding. Returns nil if not found
// or if the binding has expired.
func (t *PersistentNATTable) Lookup(srcIP netip.Addr, srcPort uint16, pool string) *PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	key := persistentNATKey{SrcIP: srcIP, SrcPort: srcPort, Pool: pool}
	b, ok := t.bindings[key]
	if !ok {
		return nil
	}
	if time.Since(b.LastSeen) > b.Timeout {
		return nil
	}
	return b
}

// Save stores a persistent NAT binding. If a binding with the same source
// IP, port, and pool already exists, LastSeen is updated to the current time.
func (t *PersistentNATTable) Save(b *PersistentNATBinding) {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := persistentNATKey{SrcIP: b.SrcIP, SrcPort: b.SrcPort, Pool: b.PoolName}
	if existing, ok := t.bindings[key]; ok {
		existing.LastSeen = time.Now()
		return
	}
	t.bindings[key] = b
}

// GC removes expired bindings. Returns the number of bindings removed.
func (t *PersistentNATTable) GC() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, b := range t.bindings {
		if now.Sub(b.LastSeen) > b.Timeout {
			delete(t.bindings, key)
			removed++
		}
	}
	return removed
}

// Clear removes all bindings.
func (t *PersistentNATTable) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.bindings = make(map[persistentNATKey]*PersistentNATBinding)
}

// Len returns the number of active bindings.
func (t *PersistentNATTable) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return len(t.bindings)
}

// All returns a snapshot of all current bindings.
func (t *PersistentNATTable) All() []*PersistentNATBinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*PersistentNATBinding, 0, len(t.bindings))
	for _, b := range t.bindings {
		result = append(result, b)
	}
	return result
}
