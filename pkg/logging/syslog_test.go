package logging

import (
	"net"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"error", SyslogError},
		{"warning", SyslogWarning},
		{"info", SyslogInfo},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := ParseSeverity(tt.name); got != tt.want {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestParseFacility(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"kern", FacilityKern},
		{"user", FacilityUser},
		{"daemon", FacilityDaemon},
		{"auth", FacilityAuth},
		{"syslog", FacilitySyslog},
		{"local0", FacilityLocal0},
		{"local1", FacilityLocal1},
		{"local2", FacilityLocal2},
		{"local3", FacilityLocal3},
		{"local4", FacilityLocal4},
		{"local5", FacilityLocal5},
		{"local6", FacilityLocal6},
		{"local7", FacilityLocal7},
		{"unknown", FacilityLocal0},
		{"", FacilityLocal0},
	}
	for _, tt := range tests {
		if got := ParseFacility(tt.name); got != tt.want {
			t.Errorf("ParseFacility(%q) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestShouldSend_NoFilter(t *testing.T) {
	c := &SyslogClient{MinSeverity: 0}
	if !c.ShouldSend(SyslogError) {
		t.Error("no filter should pass error")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("no filter should pass warning")
	}
	if !c.ShouldSend(SyslogInfo) {
		t.Error("no filter should pass info")
	}
}

func TestShouldSend_ErrorOnly(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogError}
	if !c.ShouldSend(SyslogError) {
		t.Error("error filter should pass error")
	}
	if c.ShouldSend(SyslogWarning) {
		t.Error("error filter should block warning")
	}
	if c.ShouldSend(SyslogInfo) {
		t.Error("error filter should block info")
	}
}

func TestShouldSend_WarningAndAbove(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogWarning}
	if !c.ShouldSend(SyslogError) {
		t.Error("warning filter should pass error (higher severity)")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("warning filter should pass warning")
	}
	if c.ShouldSend(SyslogInfo) {
		t.Error("warning filter should block info")
	}
}

func TestShouldSend_InfoAll(t *testing.T) {
	c := &SyslogClient{MinSeverity: SyslogInfo}
	if !c.ShouldSend(SyslogError) {
		t.Error("info filter should pass error")
	}
	if !c.ShouldSend(SyslogWarning) {
		t.Error("info filter should pass warning")
	}
	if !c.ShouldSend(SyslogInfo) {
		t.Error("info filter should pass info")
	}
}

func TestSyslogSendReceive(t *testing.T) {
	// Start a UDP listener
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)

	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := client.Send(SyslogWarning, "test message"); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	got := string(buf[:n])
	// Priority = facility*8 + severity = 16*8 + 4 = 132
	if got[:5] != "<132>" {
		t.Errorf("unexpected priority prefix: %q", got[:10])
	}
	if !contains(got, "bpfrx: test message") {
		t.Errorf("message not found in %q", got)
	}
}

func TestSyslogFacilityInPriority(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)

	client, err := NewSyslogClient("127.0.0.1", addr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.Facility = FacilityDaemon // 3

	if err := client.Send(SyslogError, "error msg"); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4096)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}

	got := string(buf[:n])
	// Priority = 3*8 + 3 = 27
	if got[:4] != "<27>" {
		t.Errorf("unexpected priority for daemon+error: %q", got[:10])
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
