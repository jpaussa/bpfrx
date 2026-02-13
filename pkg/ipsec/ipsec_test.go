package ipsec

import (
	"strings"
	"testing"

	"github.com/psaab/bpfrx/pkg/config"
)

func TestGenerateConfig_Basic(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"site-a": {
				LocalAddr:     "10.0.1.1",
				Gateway:       "10.0.2.1",
				PSK:           "supersecret",
				BindInterface: "st0.0",
			},
		},
		Proposals: map[string]*config.IPsecProposal{},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "connections {") {
		t.Error("missing connections block")
	}
	if !strings.Contains(got, "site-a {") {
		t.Error("missing connection name")
	}
	if !strings.Contains(got, "local_addrs = 10.0.1.1") {
		t.Error("missing local_addrs")
	}
	if !strings.Contains(got, "remote_addrs = 10.0.2.1") {
		t.Error("missing remote_addrs")
	}
	if !strings.Contains(got, "auth = psk") {
		t.Error("missing auth = psk")
	}
	if !strings.Contains(got, "if_id_in = 1") {
		t.Error("missing if_id_in for st0.0")
	}
	if !strings.Contains(got, "if_id_out = 1") {
		t.Error("missing if_id_out for st0.0")
	}
	if !strings.Contains(got, "secrets {") {
		t.Error("missing secrets block")
	}
	if !strings.Contains(got, `secret = "supersecret"`) {
		t.Error("missing PSK secret")
	}
}

func TestGenerateConfig_WithProposal(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "strong",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"strong": {
				Name:          "strong",
				EncryptionAlg: "aes256-cbc",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)
	if !strings.Contains(got, "esp_proposals = aes256-sha256128-modp2048") {
		t.Errorf("unexpected esp_proposals in: %s", got)
	}
}

func TestGenerateConfig_GCMNoAuth(t *testing.T) {
	m := &Manager{configDir: "/tmp", configPath: "/tmp/bpfrx.conf"}
	cfg := &config.IPsecConfig{
		VPNs: map[string]*config.IPsecVPN{
			"tun1": {
				Gateway:     "172.16.0.1",
				IPsecPolicy: "gcm",
			},
		},
		Proposals: map[string]*config.IPsecProposal{
			"gcm": {
				Name:          "gcm",
				EncryptionAlg: "aes256gcm128",
				AuthAlg:       "hmac-sha256-128",
				DHGroup:       14,
			},
		},
	}
	got := m.generateConfig(cfg)
	// GCM mode should skip auth algorithm
	if strings.Contains(got, "sha256128-modp2048") {
		t.Errorf("GCM should not include auth alg: %s", got)
	}
	if !strings.Contains(got, "esp_proposals = aes256gcm128-modp2048") {
		t.Errorf("unexpected GCM proposal: %s", got)
	}
}

func TestXfrmiIfID(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
	}{
		{"st0.0", 1},
		{"st1.0", 2},
		{"st5.0", 6},
		{"st0", 1},
		{"", 0},
		{"eth0", 0},
		{"st", 0},
	}
	for _, tt := range tests {
		if got := xfrmiIfID(tt.input); got != tt.want {
			t.Errorf("xfrmiIfID(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestDHGroupBits(t *testing.T) {
	tests := []struct {
		group int
		want  int
	}{
		{1, 768},
		{2, 1024},
		{5, 1536},
		{14, 2048},
		{15, 3072},
		{16, 4096},
		{19, 256},
		{20, 384},
		{99, 99}, // passthrough for unknown
	}
	for _, tt := range tests {
		if got := dhGroupBits(tt.group); got != tt.want {
			t.Errorf("dhGroupBits(%d) = %d, want %d", tt.group, got, tt.want)
		}
	}
}

func TestBuildESPProposal(t *testing.T) {
	tests := []struct {
		name string
		prop *config.IPsecProposal
		want string
	}{
		{
			"aes-sha256-dh14",
			&config.IPsecProposal{EncryptionAlg: "aes256-cbc", AuthAlg: "hmac-sha256-128", DHGroup: 14},
			"aes256-sha256128-modp2048",
		},
		{
			"defaults",
			&config.IPsecProposal{},
			"aes256",
		},
		{
			"gcm-no-auth",
			&config.IPsecProposal{EncryptionAlg: "aes256gcm128", AuthAlg: "hmac-sha512", DHGroup: 20},
			"aes256gcm128-modp384",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildESPProposal(tt.prop); got != tt.want {
				t.Errorf("buildESPProposal() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSAOutput(t *testing.T) {
	output := `site-a: #1, ESTABLISHED
  local: 10.0.1.1 === 10.0.2.1
  site-a: #1, reqid 1, INSTALLED
    local_ts = 10.0.1.0/24
    remote_ts = 10.0.2.0/24
`
	sas := parseSAOutput(output)
	if len(sas) != 1 {
		t.Fatalf("expected 1 SA, got %d", len(sas))
	}
	if sas[0].Name != "site-a" {
		t.Errorf("name = %q, want %q", sas[0].Name, "site-a")
	}
	if sas[0].LocalAddr != "10.0.1.1" {
		t.Errorf("local addr = %q, want %q", sas[0].LocalAddr, "10.0.1.1")
	}
	if sas[0].RemoteAddr != "10.0.2.1" {
		t.Errorf("remote addr = %q, want %q", sas[0].RemoteAddr, "10.0.2.1")
	}
}

func TestParseSAOutput_Empty(t *testing.T) {
	sas := parseSAOutput("")
	if len(sas) != 0 {
		t.Errorf("expected 0 SAs for empty input, got %d", len(sas))
	}
}

func TestParseSAOutput_Multiple(t *testing.T) {
	output := `site-a: #1, ESTABLISHED
  local: 10.0.1.1 === 10.0.2.1
site-b: #2, CONNECTING
  local: 10.0.1.1 === 10.0.3.1
`
	sas := parseSAOutput(output)
	if len(sas) != 2 {
		t.Fatalf("expected 2 SAs, got %d", len(sas))
	}
	if sas[0].Name != "site-a" {
		t.Errorf("sa[0] name = %q", sas[0].Name)
	}
	if sas[1].Name != "site-b" {
		t.Errorf("sa[1] name = %q", sas[1].Name)
	}
	if sas[1].State != "CONNECTING" {
		t.Errorf("sa[1] state = %q, want CONNECTING", sas[1].State)
	}
}
