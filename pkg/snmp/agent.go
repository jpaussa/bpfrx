package snmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/psaab/bpfrx/pkg/config"
)

// SNMP v2c PDU types.
const (
	tagInteger          = 0x02
	tagOctetString      = 0x04
	tagNull             = 0x05
	tagObjectIdentifier = 0x06
	tagSequence         = 0x30

	pduGetRequest     = 0xa0
	pduGetNextRequest = 0xa1
	pduGetResponse    = 0xa2
	pduGetBulkRequest = 0xa5

	// SNMP error codes.
	errNoError    = 0
	errTooBig     = 1
	errNoSuchName = 2
	errGenErr     = 5

	// Implicit tags for exception values (context-specific, primitive).
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82

	snmpVersion2c = 1 // version field: 0 = v1, 1 = v2c

	maxPacketSize = 4096
)

// OID constants for the system MIB group (1.3.6.1.2.1.1).
var (
	oidSysDescr    = []int{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = []int{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = []int{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = []int{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = []int{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = []int{1, 3, 6, 1, 2, 1, 1, 6, 0}

	// Ordered list of all OIDs we serve, for GETNEXT walking.
	allOIDs = [][]int{
		oidSysDescr,
		oidSysObjectID,
		oidSysUpTime,
		oidSysContact,
		oidSysName,
		oidSysLocation,
	}

	// The system MIB subtree root for walk boundary.
	oidSystemPrefix = []int{1, 3, 6, 1, 2, 1, 1}
)

// Agent is an SNMP v2c agent that serves the system MIB group.
type Agent struct {
	cfg       *config.SNMPConfig
	conn      *net.UDPConn
	startTime time.Time
	mu        sync.Mutex
	stopped   bool
}

// NewAgent creates a new SNMP agent with the given configuration.
func NewAgent(cfg *config.SNMPConfig) *Agent {
	return &Agent{
		cfg:       cfg,
		startTime: time.Now(),
	}
}

// Start begins listening for SNMP requests on UDP port 161.
// It blocks until the context is cancelled.
func (a *Agent) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", ":161")
	if err != nil {
		return fmt.Errorf("snmp: resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("snmp: listen: %w", err)
	}

	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()

	slog.Info("SNMP agent listening", "addr", ":161")

	go func() {
		<-ctx.Done()
		a.Stop()
	}()

	buf := make([]byte, maxPacketSize)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			a.mu.Lock()
			stopped := a.stopped
			a.mu.Unlock()
			if stopped {
				return nil
			}
			slog.Error("SNMP read error", "err", err)
			continue
		}

		resp := a.handlePacket(buf[:n])
		if resp != nil {
			if _, err := conn.WriteToUDP(resp, remoteAddr); err != nil {
				slog.Error("SNMP write error", "err", err, "remote", remoteAddr)
			}
		}
	}
}

// Stop shuts down the SNMP agent.
func (a *Agent) Stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	if a.conn != nil {
		a.conn.Close()
		a.conn = nil
	}
	slog.Info("SNMP agent stopped")
}

// handlePacket decodes an SNMP v2c request and produces a response.
func (a *Agent) handlePacket(data []byte) []byte {
	// Decode the outer SEQUENCE.
	tag, msgBody, err := berDecodeHeader(data)
	if err != nil || tag != tagSequence {
		slog.Debug("SNMP: invalid packet, not a SEQUENCE")
		return nil
	}

	// Decode version.
	version, rest, err := berDecodeInteger(msgBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode version")
		return nil
	}
	if version != snmpVersion2c {
		slog.Debug("SNMP: unsupported version", "version", version)
		return nil
	}

	// Decode community string.
	community, rest, err := berDecodeOctetString(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode community")
		return nil
	}

	// Verify community string.
	if !a.isValidCommunity(string(community)) {
		slog.Debug("SNMP: invalid community", "community", string(community))
		return nil
	}

	// Decode PDU.
	pduTag, pduBody, err := berDecodeHeader(rest)
	if err != nil {
		slog.Debug("SNMP: failed to decode PDU header")
		return nil
	}

	switch pduTag {
	case pduGetRequest:
		return a.handleGet(community, pduBody)
	case pduGetNextRequest:
		return a.handleGetNext(community, pduBody)
	case pduGetBulkRequest:
		return a.handleGetBulk(community, pduBody)
	default:
		slog.Debug("SNMP: unsupported PDU type", "type", pduTag)
		return nil
	}
}

// handleGet processes a GET request.
func (a *Agent) handleGet(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GET PDU", "err", err)
		return nil
	}

	var varbinds []varbind
	for _, oid := range oids {
		val, valTag := a.getOIDValue(oid)
		if val == nil {
			// For v2c GET, return noSuchObject exception.
			varbinds = append(varbinds, varbind{oid: oid, tag: tagNoSuchInstance, value: nil})
		} else {
			varbinds = append(varbinds, varbind{oid: oid, tag: valTag, value: val})
		}
	}

	return a.buildResponse(community, requestID, errNoError, 0, varbinds)
}

// handleGetNext processes a GETNEXT request.
func (a *Agent) handleGetNext(community []byte, pduBody []byte) []byte {
	requestID, _, _, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GETNEXT PDU", "err", err)
		return nil
	}

	var varbinds []varbind
	for _, oid := range oids {
		nextOID := a.findNextOID(oid)
		if nextOID == nil {
			// End of MIB view.
			varbinds = append(varbinds, varbind{oid: oid, tag: tagEndOfMibView, value: nil})
		} else {
			val, valTag := a.getOIDValue(nextOID)
			varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
		}
	}

	return a.buildResponse(community, requestID, errNoError, 0, varbinds)
}

// handleGetBulk processes a GETBULK request (RFC 3416).
func (a *Agent) handleGetBulk(community []byte, pduBody []byte) []byte {
	requestID, nonRepeaters, maxRepetitions, oids, err := decodePDUFields(pduBody)
	if err != nil {
		slog.Debug("SNMP: failed to decode GETBULK PDU", "err", err)
		return nil
	}

	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}
	if maxRepetitions > 100 {
		maxRepetitions = 100 // safety cap
	}

	var varbinds []varbind

	// Process non-repeaters (like GETNEXT for first N OIDs).
	for i := 0; i < nonRepeaters && i < len(oids); i++ {
		nextOID := a.findNextOID(oids[i])
		if nextOID == nil {
			varbinds = append(varbinds, varbind{oid: oids[i], tag: tagEndOfMibView, value: nil})
		} else {
			val, valTag := a.getOIDValue(nextOID)
			varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
		}
	}

	// Process repeaters.
	for i := nonRepeaters; i < len(oids); i++ {
		currentOID := oids[i]
		for j := 0; j < maxRepetitions; j++ {
			nextOID := a.findNextOID(currentOID)
			if nextOID == nil {
				varbinds = append(varbinds, varbind{oid: currentOID, tag: tagEndOfMibView, value: nil})
				break
			}
			val, valTag := a.getOIDValue(nextOID)
			varbinds = append(varbinds, varbind{oid: nextOID, tag: valTag, value: val})
			currentOID = nextOID
		}
	}

	return a.buildResponse(community, requestID, errNoError, 0, varbinds)
}

// isValidCommunity checks if the given community string is configured.
func (a *Agent) isValidCommunity(community string) bool {
	if a.cfg == nil || a.cfg.Communities == nil {
		return false
	}
	for _, c := range a.cfg.Communities {
		if c.Name == community {
			return true
		}
	}
	return false
}

// getOIDValue returns the encoded value and BER tag for a given OID.
func (a *Agent) getOIDValue(oid []int) ([]byte, byte) {
	if oidEqual(oid, oidSysDescr) {
		desc := "bpfrx eBPF firewall"
		if a.cfg != nil && a.cfg.Description != "" {
			desc = a.cfg.Description
		}
		return []byte(desc), tagOctetString
	}
	if oidEqual(oid, oidSysObjectID) {
		// Return a generic enterprise OID.
		return berEncodeOID([]int{1, 3, 6, 1, 4, 1, 99999, 1}), tagObjectIdentifier
	}
	if oidEqual(oid, oidSysUpTime) {
		uptime := time.Since(a.startTime)
		hundredths := int(uptime.Milliseconds() / 10)
		return berEncodeTimeTicks(hundredths), tagTimeTicks
	}
	if oidEqual(oid, oidSysContact) {
		contact := ""
		if a.cfg != nil {
			contact = a.cfg.Contact
		}
		return []byte(contact), tagOctetString
	}
	if oidEqual(oid, oidSysName) {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}
		return []byte(hostname), tagOctetString
	}
	if oidEqual(oid, oidSysLocation) {
		location := ""
		if a.cfg != nil {
			location = a.cfg.Location
		}
		return []byte(location), tagOctetString
	}
	return nil, 0
}

// findNextOID returns the next OID in the tree after the given OID, or nil.
func (a *Agent) findNextOID(oid []int) []int {
	for _, candidate := range allOIDs {
		if oidCompare(candidate, oid) > 0 {
			return candidate
		}
	}
	return nil
}

// varbind holds a single OID-value binding.
type varbind struct {
	oid   []int
	tag   byte
	value []byte
}

// buildResponse constructs a complete SNMP v2c response packet.
func (a *Agent) buildResponse(community []byte, requestID int, errorStatus int, errorIndex int, varbinds []varbind) []byte {
	// Encode varbind list.
	var vbListBytes []byte
	for _, vb := range varbinds {
		oidBytes := berEncodeTLV(tagObjectIdentifier, berEncodeOID(vb.oid))
		var valBytes []byte
		if vb.tag == tagNoSuchObject || vb.tag == tagNoSuchInstance || vb.tag == tagEndOfMibView {
			valBytes = berEncodeTLV(vb.tag, nil)
		} else {
			valBytes = berEncodeValue(vb.tag, vb.value)
		}
		pair := append(oidBytes, valBytes...)
		vbListBytes = append(vbListBytes, berEncodeTLV(tagSequence, pair)...)
	}
	vbListEncoded := berEncodeTLV(tagSequence, vbListBytes)

	// Encode PDU body: request-id, error-status, error-index, varbind-list.
	pduBody := berEncodeIntegerTLV(requestID)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorStatus)...)
	pduBody = append(pduBody, berEncodeIntegerTLV(errorIndex)...)
	pduBody = append(pduBody, vbListEncoded...)

	pduEncoded := berEncodeTLV(pduGetResponse, pduBody)

	// Encode message: version, community, PDU.
	msgBody := berEncodeIntegerTLV(snmpVersion2c)
	msgBody = append(msgBody, berEncodeTLV(tagOctetString, community)...)
	msgBody = append(msgBody, pduEncoded...)

	return berEncodeTLV(tagSequence, msgBody)
}

// --- BER encoding helpers ---

// tagTimeTicks is the ASN.1 application tag for TimeTicks (hundredths of a second).
const tagTimeTicks = 0x43

// berEncodeTLV encodes a tag-length-value triplet.
func berEncodeTLV(tag byte, value []byte) []byte {
	length := len(value)
	var buf []byte
	buf = append(buf, tag)
	buf = append(buf, berEncodeLength(length)...)
	buf = append(buf, value...)
	return buf
}

// berEncodeLength encodes a BER length field.
func berEncodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	// Multi-byte length.
	var lenBytes []byte
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...)
}

// berEncodeIntegerTLV encodes an integer as a complete TLV.
func berEncodeIntegerTLV(val int) []byte {
	return berEncodeTLV(tagInteger, berEncodeIntegerValue(val))
}

// berEncodeIntegerValue encodes an integer value (without tag/length).
func berEncodeIntegerValue(val int) []byte {
	if val == 0 {
		return []byte{0}
	}

	// Convert to big-endian bytes with proper sign handling.
	var bytes []byte
	if val > 0 {
		for v := val; v > 0; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		// If high bit set, prepend a zero byte (positive number must not look negative).
		if bytes[0]&0x80 != 0 {
			bytes = append([]byte{0}, bytes...)
		}
	} else {
		// Negative: two's complement encoding.
		for v := val; v < -1; v >>= 8 {
			bytes = append([]byte{byte(v & 0xff)}, bytes...)
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xff}, bytes...)
		}
	}
	return bytes
}

// berEncodeTimeTicks encodes a TimeTicks value (unsigned 32-bit integer).
func berEncodeTimeTicks(hundredths int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(hundredths))
	// Strip leading zeros but keep at least one byte.
	for len(buf) > 1 && buf[0] == 0 {
		buf = buf[1:]
	}
	return buf
}

// berEncodeOID encodes an OID value (without tag/length).
func berEncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	// First two components are combined: first*40 + second.
	var encoded []byte
	encoded = append(encoded, byte(oid[0]*40+oid[1]))
	for i := 2; i < len(oid); i++ {
		encoded = append(encoded, berEncodeSubID(oid[i])...)
	}
	return encoded
}

// berEncodeSubID encodes a single OID sub-identifier using base-128 encoding.
func berEncodeSubID(val int) []byte {
	if val < 0x80 {
		return []byte{byte(val)}
	}
	var bytes []byte
	for v := val; v > 0; v >>= 7 {
		bytes = append([]byte{byte(v & 0x7f)}, bytes...)
	}
	// Set high bit on all but the last byte.
	for i := 0; i < len(bytes)-1; i++ {
		bytes[i] |= 0x80
	}
	return bytes
}

// berEncodeValue encodes a value with the given tag.
func berEncodeValue(tag byte, value []byte) []byte {
	return berEncodeTLV(tag, value)
}

// --- BER decoding helpers ---

// berDecodeHeader decodes a BER TLV header, returning the tag, the value bytes, and any error.
func berDecodeHeader(data []byte) (byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: data too short")
	}
	tag := data[0]
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: value truncated (need %d, have %d)", headerLen+length, len(data))
	}
	return tag, data[headerLen : headerLen+length], nil
}

// berDecodeLength decodes a BER length field.
// Returns the length value and the number of bytes consumed.
func berDecodeLength(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("ber: empty length")
	}
	if data[0] < 0x80 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("ber: unsupported length encoding (%d bytes)", numBytes)
	}
	if len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("ber: length bytes truncated")
	}
	length := 0
	for i := 0; i < numBytes; i++ {
		length = (length << 8) | int(data[1+i])
	}
	return length, 1 + numBytes, nil
}

// berDecodeInteger decodes a BER INTEGER, returning the value and remaining bytes.
func berDecodeInteger(data []byte) (int, []byte, error) {
	if len(data) < 2 {
		return 0, nil, fmt.Errorf("ber: integer too short")
	}
	if data[0] != tagInteger {
		return 0, nil, fmt.Errorf("ber: expected INTEGER (0x02), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return 0, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return 0, nil, fmt.Errorf("ber: integer value truncated")
	}
	valBytes := data[headerLen : headerLen+length]
	val := 0
	// Sign-extend from first byte.
	if len(valBytes) > 0 && valBytes[0]&0x80 != 0 {
		val = -1
	}
	for _, b := range valBytes {
		val = (val << 8) | int(b)
	}
	return val, data[headerLen+length:], nil
}

// berDecodeOctetString decodes a BER OCTET STRING, returning the value and remaining bytes.
func berDecodeOctetString(data []byte) ([]byte, []byte, error) {
	if len(data) < 2 {
		return nil, nil, fmt.Errorf("ber: octet string too short")
	}
	if data[0] != tagOctetString {
		return nil, nil, fmt.Errorf("ber: expected OCTET STRING (0x04), got 0x%02x", data[0])
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return nil, nil, err
	}
	headerLen := 1 + lenBytes
	if headerLen+length > len(data) {
		return nil, nil, fmt.Errorf("ber: octet string truncated")
	}
	return data[headerLen : headerLen+length], data[headerLen+length:], nil
}

// berDecodeOID decodes the raw bytes of a BER-encoded OID value into integer components.
func berDecodeOID(data []byte) ([]int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ber: empty OID")
	}
	// First byte encodes first two components: first = byte/40, second = byte%40.
	oid := []int{int(data[0]) / 40, int(data[0]) % 40}
	i := 1
	for i < len(data) {
		val := 0
		for {
			if i >= len(data) {
				return nil, fmt.Errorf("ber: OID sub-identifier truncated")
			}
			val = (val << 7) | int(data[i]&0x7f)
			if data[i]&0x80 == 0 {
				i++
				break
			}
			i++
		}
		oid = append(oid, val)
	}
	return oid, nil
}

// decodePDUFields decodes the common PDU fields: request-id, error-status/non-repeaters,
// error-index/max-repetitions, and the varbind list of OIDs.
func decodePDUFields(data []byte) (requestID int, field2 int, field3 int, oids [][]int, err error) {
	// request-id
	requestID, rest, err := berDecodeInteger(data)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("request-id: %w", err)
	}

	// error-status or non-repeaters
	field2, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field2: %w", err)
	}

	// error-index or max-repetitions
	field3, rest, err = berDecodeInteger(rest)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("field3: %w", err)
	}

	// varbind list (SEQUENCE of SEQUENCE).
	if len(rest) == 0 {
		return requestID, field2, field3, nil, nil
	}
	tag, vbListBody, err := berDecodeHeader(rest)
	if err != nil || tag != tagSequence {
		return 0, 0, 0, nil, fmt.Errorf("varbind list: not a SEQUENCE")
	}

	// Decode each varbind (SEQUENCE { OID, value }).
	remaining := vbListBody
	for len(remaining) > 0 {
		tag, vbBody, err := berDecodeHeader(remaining)
		if err != nil || tag != tagSequence {
			return 0, 0, 0, nil, fmt.Errorf("varbind: not a SEQUENCE")
		}
		// Advance past this varbind in the remaining buffer.
		consumed := len(remaining) - len(vbBody)
		// We need to figure out total consumed length including value.
		// Re-decode to get the exact offset.
		vbTotalLen := berEncodedLen(remaining)
		if vbTotalLen <= 0 || vbTotalLen > len(remaining) {
			break
		}
		remaining = remaining[vbTotalLen:]
		_ = consumed // unused

		// Decode OID from varbind body.
		if len(vbBody) < 2 {
			continue
		}
		if vbBody[0] != tagObjectIdentifier {
			continue
		}
		oidLen, oidLenBytes, err := berDecodeLength(vbBody[1:])
		if err != nil {
			continue
		}
		oidHeaderLen := 1 + oidLenBytes
		if oidHeaderLen+oidLen > len(vbBody) {
			continue
		}
		oid, err := berDecodeOID(vbBody[oidHeaderLen : oidHeaderLen+oidLen])
		if err != nil {
			continue
		}
		oids = append(oids, oid)
	}

	return requestID, field2, field3, oids, nil
}

// berEncodedLen returns the total encoded length of a BER TLV at the start of data.
func berEncodedLen(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	length, lenBytes, err := berDecodeLength(data[1:])
	if err != nil {
		return -1
	}
	return 1 + lenBytes + length
}

// --- OID comparison helpers ---

// oidEqual returns true if two OIDs are identical.
func oidEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// oidCompare compares two OIDs lexicographically.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func oidCompare(a, b []int) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
