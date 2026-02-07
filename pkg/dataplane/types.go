// Package dataplane manages eBPF program loading, map operations,
// and XDP/TC attachment for the bpfrx firewall dataplane.
package dataplane

// SessionKey mirrors the C struct session_key (5-tuple).
type SessionKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Pad      [3]byte
}

// SessionValue mirrors the C struct session_value.
type SessionValue struct {
	State     uint8
	Flags     uint8
	TCPState  uint8
	IsReverse uint8

	Created  uint64
	LastSeen uint64
	Timeout  uint32
	PolicyID uint32

	IngressZone uint16
	EgressZone  uint16

	NATSrcIP   [4]byte
	NATDstIP   [4]byte
	NATSrcPort uint16
	NATDstPort uint16

	FwdPackets uint64
	FwdBytes   uint64
	RevPackets uint64
	RevBytes   uint64

	ReverseKey SessionKey

	ALGType  uint8
	LogFlags uint8
	Pad      [2]byte
}

// ZoneConfig mirrors the C struct zone_config.
type ZoneConfig struct {
	ZoneID          uint16
	ScreenProfileID uint16
	HostInbound     uint32
}

// ZonePairKey mirrors the C struct zone_pair_key.
type ZonePairKey struct {
	FromZone uint16
	ToZone   uint16
}

// PolicySet mirrors the C struct policy_set.
type PolicySet struct {
	PolicySetID   uint32
	NumRules      uint16
	DefaultAction uint16
}

// PolicyRule mirrors the C struct policy_rule.
type PolicyRule struct {
	RuleID      uint32
	PolicySetID uint32
	Sequence    uint16
	Action      uint8
	Log         uint8

	SrcAddrID  uint32
	DstAddrID  uint32
	DstPortLow  uint16
	DstPortHigh uint16
	Protocol   uint8
	Pad        [3]byte

	AppID     uint32
	NATRuleID uint32
	CounterID uint32
}

// CounterValue mirrors the C struct counter_value.
type CounterValue struct {
	Packets uint64
	Bytes   uint64
}

// Event mirrors the C struct event.
type Event struct {
	Timestamp      uint64
	SrcIP          [4]byte
	DstIP          [4]byte
	SrcPort        uint16
	DstPort        uint16
	PolicyID       uint32
	IngressZone    uint16
	EgressZone     uint16
	EventType      uint8
	Protocol       uint8
	Action         uint8
	Pad            uint8
	SessionPackets uint64
	SessionBytes   uint64
}

// Tail call program indices -- must match C constants.
const (
	XDPProgScreen    = 0
	XDPProgZone      = 1
	XDPProgConntrack = 2
	XDPProgPolicy    = 3
	XDPProgNAT       = 4
	XDPProgForward   = 5

	TCProgConntrack   = 0
	TCProgNAT         = 1
	TCProgScreenEgress = 2
	TCProgForward     = 3
)

// Global counter indices -- must match C constants.
const (
	GlobalCtrRxPackets    = 0
	GlobalCtrTxPackets    = 1
	GlobalCtrDrops        = 2
	GlobalCtrSessionsNew  = 3
	GlobalCtrSessionsClosed = 4
	GlobalCtrScreenDrops  = 5
	GlobalCtrPolicyDeny   = 6
	GlobalCtrNATAllocFail = 7
	GlobalCtrMax          = 8
)

// Session state constants.
const (
	SessStateNone        = 0
	SessStateNew         = 1
	SessStateSynSent     = 2
	SessStateSynRecv     = 3
	SessStateEstablished = 4
	SessStateFINWait     = 5
	SessStateCloseWait   = 6
	SessStateTimeWait    = 7
	SessStateClosed      = 8
)

// Policy action constants.
const (
	ActionDeny   = 0
	ActionPermit = 1
	ActionReject = 2
)
