package logging

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Syslog severity levels (RFC 3164).
const (
	SyslogError   = 3
	SyslogWarning = 4
	SyslogInfo    = 6
)

// Syslog facility codes (RFC 3164).
const (
	FacilityKern     = 0
	FacilityUser     = 1
	FacilityDaemon   = 3
	FacilityAuth     = 4
	FacilitySyslog   = 5
	FacilityLocal0   = 16
	FacilityLocal1   = 17
	FacilityLocal2   = 18
	FacilityLocal3   = 19
	FacilityLocal4   = 20
	FacilityLocal5   = 21
	FacilityLocal6   = 22
	FacilityLocal7   = 23
)

// SyslogClient sends UDP syslog messages (RFC 3164).
type SyslogClient struct {
	conn        net.Conn
	hostname    string
	Facility    int // syslog facility code (default: FacilityLocal0)
	MinSeverity int // 0 = no filter, else SyslogError(3)/SyslogWarning(4)/SyslogInfo(6)
}

// NewSyslogClient creates a new UDP syslog client connected to host:port.
func NewSyslogClient(host string, port int) (*SyslogClient, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial syslog %s: %w", addr, err)
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "bpfrx"
	}
	return &SyslogClient{conn: conn, hostname: hostname, Facility: FacilityLocal0}, nil
}

// Send sends a syslog message with the given severity.
func (s *SyslogClient) Send(severity int, msg string) error {
	priority := s.Facility*8 + severity
	ts := time.Now().Format(time.Stamp) // "Jan _2 15:04:05"
	line := fmt.Sprintf("<%d>%s %s bpfrx: %s", priority, ts, s.hostname, msg)
	_, err := s.conn.Write([]byte(line))
	return err
}

// ShouldSend returns true if the event severity passes this client's filter.
// Lower severity number = higher priority (error=3 < warning=4 < info=6).
func (s *SyslogClient) ShouldSend(severity int) bool {
	return s.MinSeverity == 0 || severity <= s.MinSeverity
}

// ParseSeverity converts a severity name to its numeric value.
// Returns 0 (no filter) for unrecognized names.
func ParseSeverity(name string) int {
	switch name {
	case "error":
		return SyslogError
	case "warning":
		return SyslogWarning
	case "info":
		return SyslogInfo
	default:
		return 0
	}
}

// ParseFacility converts a facility name to its numeric code.
// Returns FacilityLocal0 for unrecognized names.
func ParseFacility(name string) int {
	switch name {
	case "kern":
		return FacilityKern
	case "user":
		return FacilityUser
	case "daemon":
		return FacilityDaemon
	case "auth":
		return FacilityAuth
	case "syslog":
		return FacilitySyslog
	case "local0":
		return FacilityLocal0
	case "local1":
		return FacilityLocal1
	case "local2":
		return FacilityLocal2
	case "local3":
		return FacilityLocal3
	case "local4":
		return FacilityLocal4
	case "local5":
		return FacilityLocal5
	case "local6":
		return FacilityLocal6
	case "local7":
		return FacilityLocal7
	default:
		return FacilityLocal0
	}
}

// Close closes the underlying connection.
func (s *SyslogClient) Close() error {
	return s.conn.Close()
}
