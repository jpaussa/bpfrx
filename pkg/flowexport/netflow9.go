// Package flowexport implements NetFlow v9 flow data export.
package flowexport

import (
	"encoding/binary"
	"net"
	"time"
)

// NetFlow v9 field type IDs (RFC 3954).
const (
	fieldInBytes          = 1
	fieldInPkts           = 2
	fieldProtocol         = 4
	fieldSrcTos           = 5
	fieldTCPFlags         = 6
	fieldL4SrcPort        = 7
	fieldIPv4SrcAddr      = 8
	fieldSrcMask          = 9
	fieldInputSNMP        = 10
	fieldL4DstPort        = 11
	fieldIPv4DstAddr      = 12
	fieldDstMask          = 13
	fieldOutputSNMP       = 14
	fieldLastSwitched      = 21
	fieldFirstSwitched     = 22
	fieldIPv6SrcAddr      = 27
	fieldIPv6DstAddr      = 28
	fieldIPv6SrcMask      = 29
	fieldIPv6DstMask      = 30
	fieldDirection        = 61
	fieldIPv4Ident        = 54
)

// Template IDs for IPv4 and IPv6.
const (
	templateIDv4 = 256
	templateIDv6 = 257
)

// flowsetIDTemplate is the FlowSet ID for template records.
const flowsetIDTemplate = 0

// Maximum UDP payload size for NetFlow packets.
const maxPayload = 1400

// templateFieldV4 defines the IPv4 template fields and their byte sizes.
var templateFieldV4 = []struct {
	fieldType uint16
	fieldLen  uint16
}{
	{fieldIPv4SrcAddr, 4},
	{fieldIPv4DstAddr, 4},
	{fieldL4SrcPort, 2},
	{fieldL4DstPort, 2},
	{fieldProtocol, 1},
	{fieldSrcTos, 1},
	{fieldTCPFlags, 1},
	{fieldDirection, 1},
	{fieldInputSNMP, 4},
	{fieldOutputSNMP, 4},
	{fieldInPkts, 8},
	{fieldInBytes, 8},
	{fieldFirstSwitched, 4},
	{fieldLastSwitched, 4},
	{fieldSrcMask, 1},
	{fieldDstMask, 1},
	// 2 bytes padding to align to 4 bytes
}

// templateFieldV6 defines the IPv6 template fields and their byte sizes.
var templateFieldV6 = []struct {
	fieldType uint16
	fieldLen  uint16
}{
	{fieldIPv6SrcAddr, 16},
	{fieldIPv6DstAddr, 16},
	{fieldL4SrcPort, 2},
	{fieldL4DstPort, 2},
	{fieldProtocol, 1},
	{fieldSrcTos, 1},
	{fieldTCPFlags, 1},
	{fieldDirection, 1},
	{fieldInputSNMP, 4},
	{fieldOutputSNMP, 4},
	{fieldInPkts, 8},
	{fieldInBytes, 8},
	{fieldFirstSwitched, 4},
	{fieldLastSwitched, 4},
	{fieldIPv6SrcMask, 1},
	{fieldIPv6DstMask, 1},
	// 2 bytes padding to align to 4 bytes
}

// recordSizeV4 is the byte size of a single IPv4 data record.
const recordSizeV4 = 4 + 4 + 2 + 2 + 1 + 1 + 1 + 1 + 4 + 4 + 8 + 8 + 4 + 4 + 1 + 1 + 2 // 48 (incl padding)

// recordSizeV6 is the byte size of a single IPv6 data record.
const recordSizeV6 = 16 + 16 + 2 + 2 + 1 + 1 + 1 + 1 + 4 + 4 + 8 + 8 + 4 + 4 + 1 + 1 + 2 // 72 (incl padding)

// FlowRecord holds the data for a single NetFlow record.
type FlowRecord struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  uint8
	TOS       uint8
	TCPFlags  uint8
	Direction uint8
	InIf      uint32
	OutIf     uint32
	Packets   uint64
	Bytes     uint64
	StartTime time.Time
	EndTime   time.Time
	SrcMask   uint8
	DstMask   uint8
	IsIPv6    bool
}

// nfHeader is the 20-byte NetFlow v9 packet header.
type nfHeader struct {
	Version    uint16
	Count      uint16
	SysUptime  uint32 // milliseconds since boot
	UnixSecs   uint32
	SeqNumber  uint32
	SourceID   uint32
}

func encodeHeader(h nfHeader) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Count)
	binary.BigEndian.PutUint32(b[4:8], h.SysUptime)
	binary.BigEndian.PutUint32(b[8:12], h.UnixSecs)
	binary.BigEndian.PutUint32(b[12:16], h.SeqNumber)
	binary.BigEndian.PutUint32(b[16:20], h.SourceID)
	return b
}

// encodeTemplateFlowSet builds a template FlowSet containing both v4 and v6 templates.
func encodeTemplateFlowSet() []byte {
	// Each template: 4-byte header (ID + field count) + N * 4-byte field entries
	v4fields := len(templateFieldV4)
	v6fields := len(templateFieldV6)
	// FlowSet header (4 bytes) + 2 template headers (4 each) + field entries
	totalLen := 4 + (4 + v4fields*4) + (4 + v6fields*4)
	// Pad to 4-byte boundary (already aligned since fields are 4 bytes each)

	b := make([]byte, totalLen)
	off := 0

	// FlowSet header: ID=0 (template), Length
	binary.BigEndian.PutUint16(b[off:off+2], flowsetIDTemplate)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	// IPv4 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv4)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(v4fields))
	off += 4
	for _, f := range templateFieldV4 {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	// IPv6 template
	binary.BigEndian.PutUint16(b[off:off+2], templateIDv6)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(v6fields))
	off += 4
	for _, f := range templateFieldV6 {
		binary.BigEndian.PutUint16(b[off:off+2], f.fieldType)
		binary.BigEndian.PutUint16(b[off+2:off+4], f.fieldLen)
		off += 4
	}

	return b
}

// encodeDataFlowSet builds a data FlowSet from a batch of records.
// All records in a batch must be the same AF (v4 or v6).
func encodeDataFlowSet(records []FlowRecord, bootTime time.Time) []byte {
	if len(records) == 0 {
		return nil
	}
	isV6 := records[0].IsIPv6
	var tmplID uint16
	var recSize int
	if isV6 {
		tmplID = templateIDv6
		recSize = recordSizeV6
	} else {
		tmplID = templateIDv4
		recSize = recordSizeV4
	}

	// FlowSet header (4 bytes) + records
	totalLen := 4 + len(records)*recSize
	// Pad to 4-byte boundary
	pad := (4 - totalLen%4) % 4
	totalLen += pad

	b := make([]byte, totalLen)
	off := 0

	// FlowSet header
	binary.BigEndian.PutUint16(b[off:off+2], tmplID)
	binary.BigEndian.PutUint16(b[off+2:off+4], uint16(totalLen))
	off += 4

	for _, r := range records {
		if isV6 {
			off = encodeRecordV6(b, off, r, bootTime)
		} else {
			off = encodeRecordV4(b, off, r, bootTime)
		}
	}

	return b
}

func encodeRecordV4(b []byte, off int, r FlowRecord, bootTime time.Time) int {
	src4 := r.SrcIP.To4()
	dst4 := r.DstIP.To4()
	if src4 == nil {
		src4 = net.IPv4zero.To4()
	}
	if dst4 == nil {
		dst4 = net.IPv4zero.To4()
	}
	copy(b[off:off+4], src4)
	off += 4
	copy(b[off:off+4], dst4)
	off += 4
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	b[off] = r.TOS
	off++
	b[off] = r.TCPFlags
	off++
	b[off] = r.Direction
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// 2 bytes padding
	off += 2
	return off
}

func encodeRecordV6(b []byte, off int, r FlowRecord, bootTime time.Time) int {
	src16 := r.SrcIP.To16()
	dst16 := r.DstIP.To16()
	if src16 == nil {
		src16 = net.IPv6zero
	}
	if dst16 == nil {
		dst16 = net.IPv6zero
	}
	copy(b[off:off+16], src16)
	off += 16
	copy(b[off:off+16], dst16)
	off += 16
	binary.BigEndian.PutUint16(b[off:off+2], r.SrcPort)
	off += 2
	binary.BigEndian.PutUint16(b[off:off+2], r.DstPort)
	off += 2
	b[off] = r.Protocol
	off++
	b[off] = r.TOS
	off++
	b[off] = r.TCPFlags
	off++
	b[off] = r.Direction
	off++
	binary.BigEndian.PutUint32(b[off:off+4], r.InIf)
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], r.OutIf)
	off += 4
	binary.BigEndian.PutUint64(b[off:off+8], r.Packets)
	off += 8
	binary.BigEndian.PutUint64(b[off:off+8], r.Bytes)
	off += 8
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.StartTime))
	off += 4
	binary.BigEndian.PutUint32(b[off:off+4], uptimeMs(bootTime, r.EndTime))
	off += 4
	b[off] = r.SrcMask
	off++
	b[off] = r.DstMask
	off++
	// 2 bytes padding
	off += 2
	return off
}

func uptimeMs(boot, t time.Time) uint32 {
	d := t.Sub(boot)
	if d < 0 {
		return 0
	}
	return uint32(d.Milliseconds())
}
