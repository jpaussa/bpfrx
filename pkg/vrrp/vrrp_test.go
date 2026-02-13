package vrrp

import (
	"strings"
	"testing"
)

func TestGenerateConfig_Basic(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          200,
			Preempt:           true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)

	checks := []string{
		"vrrp_instance VI_trust0_100",
		"state BACKUP",
		"interface trust0",
		"virtual_router_id 100",
		"priority 200",
		"advert_int 1",
		"10.0.1.1/24 dev trust0",
	}
	for _, want := range checks {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// With preempt=true, should NOT have "nopreempt"
	if strings.Contains(got, "nopreempt") {
		t.Error("unexpected nopreempt with Preempt=true")
	}
}

func TestGenerateConfig_NoPreempt(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           false,
			AdvertiseInterval: 2,
			VirtualAddresses:  []string{"10.0.1.1"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "nopreempt") {
		t.Error("missing nopreempt")
	}
	if !strings.Contains(got, "advert_int 2") {
		t.Error("missing advert_int 2")
	}
	// VIP without CIDR should get /32
	if !strings.Contains(got, "10.0.1.1/32 dev trust0") {
		t.Errorf("expected /32 suffix for VIP without CIDR, got:\n%s", got)
	}
}

func TestGenerateConfig_Auth(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           true,
			AdvertiseInterval: 1,
			AuthType:          "md5",
			AuthKey:           "secret123",
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "auth_type AH") {
		t.Error("missing auth_type AH for md5")
	}
	if !strings.Contains(got, "auth_pass secret123") {
		t.Error("missing auth_pass")
	}
}

func TestGenerateConfig_AuthPass(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			Preempt:           true,
			AdvertiseInterval: 1,
			AuthType:          "",
			AuthKey:           "mykey",
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "auth_type PASS") {
		t.Error("missing auth_type PASS for non-md5")
	}
}

func TestGenerateConfig_TrackInterface(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          200,
			Preempt:           true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
			TrackInterface:    "untrust0",
			TrackPriorityCost: 100,
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "track_interface") {
		t.Error("missing track_interface section")
	}
	if !strings.Contains(got, "untrust0 weight -100") {
		t.Errorf("missing track weight, got:\n%s", got)
	}
}

func TestGenerateConfig_AcceptData(t *testing.T) {
	instances := []*Instance{
		{
			Interface:         "trust0",
			GroupID:           100,
			Priority:          100,
			AcceptData:        true,
			AdvertiseInterval: 1,
			VirtualAddresses:  []string{"10.0.1.1/24"},
		},
	}
	got := generateConfig(instances)
	if !strings.Contains(got, "accept") {
		t.Error("missing accept")
	}
}

func TestParseDataFile(t *testing.T) {
	data := `------< VRRP Topology >------
 VRRP Instance = VI_trust0_100
   State               = MASTER
   Last transition      = 1707868800
   Listening device     = trust0

 VRRP Instance = VI_untrust0_200
   State               = BACKUP
   Last transition      = 1707868801
`
	got := parseDataFile(data)
	if got["VI_trust0_100"] != "MASTER" {
		t.Errorf("VI_trust0_100: got %q, want MASTER", got["VI_trust0_100"])
	}
	if got["VI_untrust0_200"] != "BACKUP" {
		t.Errorf("VI_untrust0_200: got %q, want BACKUP", got["VI_untrust0_200"])
	}
}

func TestParseDataFile_Empty(t *testing.T) {
	got := parseDataFile("")
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestCollectInstances_Nil(t *testing.T) {
	instances := CollectInstances(nil)
	if instances != nil {
		t.Errorf("expected nil, got %v", instances)
	}
}
