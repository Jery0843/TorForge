package tor

import (
	"testing"
	"time"

	"github.com/jery0843/torforge/pkg/config"
)

func TestNewManager(t *testing.T) {
	cfg := &config.TorConfig{
		Binary:      "tor",
		DataDir:     "/tmp/torforge-test",
		ControlPort: 9051,
		SOCKSPort:   9050,
		TransPort:   9040,
		DNSPort:     5353,
	}

	mgr := NewManager(cfg)
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	if mgr.cfg != cfg {
		t.Error("manager config not set correctly")
	}
}

func TestIsTorInstalled(t *testing.T) {
	// This test depends on whether Tor is installed
	// We just check that it doesn't panic
	_ = IsTorInstalled()
}

func TestGetTorVersion(t *testing.T) {
	if !IsTorInstalled() {
		t.Skip("Tor not installed")
	}

	version, err := GetTorVersion()
	if err != nil {
		t.Fatalf("GetTorVersion() error = %v", err)
	}

	if version == "" {
		t.Error("GetTorVersion returned empty string")
	}
}

func TestParseBootstrapProgress(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"NOTICE BOOTSTRAP PROGRESS=0 TAG=starting", 0},
		{"NOTICE BOOTSTRAP PROGRESS=50 TAG=loading_descriptors", 50},
		{"NOTICE BOOTSTRAP PROGRESS=100 TAG=done", 100},
		{"NOTICE BOOTSTRAP PROGRESS=85 TAG=loading_descriptors SUMMARY=\"Loading\"", 85},
		{"invalid", -1},
		{"", -1},
		{"PROGRESS=", -1},
		{"NOTICE BOOTSTRAP PROGRESS=garbage PROGRESS=85 TAG=done", 85},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseBootstrapProgress(tt.input)
			if result != tt.expected {
				t.Errorf("parseBootstrapProgress(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGenerateTorrc(t *testing.T) {
	cfg := &config.TorConfig{
		DataDir:     "/var/lib/torforge",
		ControlPort: 9051,
		SOCKSPort:   9050,
		TransPort:   9040,
		DNSPort:     5353,
		ExitNodes:   "{us},{de}",
	}

	mgr := NewManager(cfg)
	torrc := mgr.generateTorrc()

	// Check required entries
	required := []string{
		"SocksPort 127.0.0.1:9050",
		"TransPort 127.0.0.1:9040",
		"DNSPort 127.0.0.1:5353",
		"ControlPort 127.0.0.1:9051",
		"CookieAuthentication 1",
		"DataDirectory /var/lib/torforge",
		"ExitNodes {us},{de}",
	}

	for _, r := range required {
		if !containsLine(torrc, r) {
			t.Errorf("torrc missing: %s", r)
		}
	}
}

func containsLine(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestManagerGetAddresses(t *testing.T) {
	cfg := &config.TorConfig{
		SOCKSPort: 9050,
		TransPort: 9040,
		DNSPort:   5353,
	}

	mgr := NewManager(cfg)

	if addr := mgr.GetSOCKSAddr(); addr != "127.0.0.1:9050" {
		t.Errorf("GetSOCKSAddr() = %s, want 127.0.0.1:9050", addr)
	}

	if addr := mgr.GetTransportAddr(); addr != "127.0.0.1:9040" {
		t.Errorf("GetTransportAddr() = %s, want 127.0.0.1:9040", addr)
	}

	if addr := mgr.GetDNSAddr(); addr != "127.0.0.1:5353" {
		t.Errorf("GetDNSAddr() = %s, want 127.0.0.1:5353", addr)
	}
}

func TestManagerNotRunning(t *testing.T) {
	cfg := &config.TorConfig{}
	mgr := NewManager(cfg)

	// NewIdentity should fail when not running
	err := mgr.NewIdentity()
	if err == nil {
		t.Error("NewIdentity should fail when not connected")
	}

	// GetExitIP should fail when not running
	_, err = mgr.GetExitIP()
	if err == nil {
		t.Error("GetExitIP should fail when not running")
	}

	// GetStatus should return not running
	status, err := mgr.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	if status.Running {
		t.Error("GetStatus().Running should be false")
	}
}

func TestParseCircuitID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"EXTENDED 123", "123"},
		{"EXTENDED 456 path", "456"},
		{"EXTENDED 789\n", "789"},
		{"250-EXTENDED 42", "42"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseCircuitID(tt.input)
			if result != tt.expected {
				t.Errorf("parseCircuitID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCircuitStats(t *testing.T) {
	// Create a mock circuit manager (without actual Tor connection)
	cfg := &config.TorConfig{}
	mgr := NewManager(cfg)

	// GetStatus should work even without circuits
	status, err := mgr.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}

	if status.ActiveCircuits != 0 {
		t.Errorf("expected 0 active circuits, got %d", status.ActiveCircuits)
	}
}

func TestManagerStop(t *testing.T) {
	cfg := &config.TorConfig{}
	mgr := NewManager(cfg)

	// Stop should be idempotent
	if err := mgr.Stop(); err != nil {
		t.Errorf("Stop() on non-running manager error = %v", err)
	}
}

func TestStatusStruct(t *testing.T) {
	status := &Status{
		Running:            true,
		Uptime:             5 * time.Minute,
		SOCKSPort:          9050,
		TransPort:          9040,
		DNSPort:            5353,
		ActiveCircuits:     3,
		CircuitEstablished: true,
		ExitIP:             "1.2.3.4",
	}

	if !status.Running {
		t.Error("Status.Running should be true")
	}

	if status.ActiveCircuits != 3 {
		t.Errorf("Status.ActiveCircuits = %d, want 3", status.ActiveCircuits)
	}
}
