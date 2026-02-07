// Package logging implements eBPF ring buffer event reading.
package logging

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/psviderski/bpfrx/pkg/dataplane"
)

// EventReader reads events from the eBPF ring buffer.
type EventReader struct {
	eventsMap *ebpf.Map
}

// NewEventReader creates a new event reader for the given events map.
func NewEventReader(eventsMap *ebpf.Map) *EventReader {
	return &EventReader{eventsMap: eventsMap}
}

// Run starts reading events. It blocks until ctx is cancelled.
func (er *EventReader) Run(ctx context.Context) {
	if er.eventsMap == nil {
		slog.Warn("events map is nil, event reader not starting")
		return
	}

	rd, err := ringbuf.NewReader(er.eventsMap)
	if err != nil {
		slog.Error("failed to create ring buffer reader", "err", err)
		return
	}
	defer rd.Close()

	slog.Info("event reader started")

	// Close the reader when context is done
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			select {
			case <-ctx.Done():
				slog.Info("event reader stopped")
				return
			default:
				slog.Error("ring buffer read error", "err", err)
				return
			}
		}

		if len(record.RawSample) < int(unsafe.Sizeof(dataplane.Event{})) {
			continue
		}

		er.logEvent(record.RawSample)
	}
}

func (er *EventReader) logEvent(data []byte) {
	var evt dataplane.Event
	evt.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	evt.SrcIP = [4]byte(data[8:12])
	evt.DstIP = [4]byte(data[12:16])
	evt.SrcPort = binary.BigEndian.Uint16(data[16:18])
	evt.DstPort = binary.BigEndian.Uint16(data[18:20])
	evt.PolicyID = binary.LittleEndian.Uint32(data[20:24])
	evt.IngressZone = binary.LittleEndian.Uint16(data[24:26])
	evt.EgressZone = binary.LittleEndian.Uint16(data[26:28])
	evt.EventType = data[28]
	evt.Protocol = data[29]
	evt.Action = data[30]

	srcIP := net.IP(evt.SrcIP[:])
	dstIP := net.IP(evt.DstIP[:])

	eventName := eventTypeName(evt.EventType)
	actionName := actionName(evt.Action)
	protoName := protoName(evt.Protocol)

	slog.Info("firewall event",
		"type", eventName,
		"src", fmt.Sprintf("%s:%d", srcIP, evt.SrcPort),
		"dst", fmt.Sprintf("%s:%d", dstIP, evt.DstPort),
		"proto", protoName,
		"action", actionName,
		"policy_id", evt.PolicyID,
		"ingress_zone", evt.IngressZone,
		"egress_zone", evt.EgressZone)
}

func eventTypeName(t uint8) string {
	switch t {
	case dataplane.EventTypeSessionOpen:
		return "SESSION_OPEN"
	case dataplane.EventTypeSessionClose:
		return "SESSION_CLOSE"
	case dataplane.EventTypePolicyDeny:
		return "POLICY_DENY"
	case dataplane.EventTypeScreenDrop:
		return "SCREEN_DROP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func actionName(a uint8) string {
	switch a {
	case dataplane.ActionPermit:
		return "permit"
	case dataplane.ActionDeny:
		return "deny"
	case dataplane.ActionReject:
		return "reject"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("%d", p)
	}
}
