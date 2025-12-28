// Package tor provides Tor process management and control
package tor

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/tor"
	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

// Manager handles Tor process lifecycle and control
type Manager struct {
	cfg       *config.TorConfig
	tor       *tor.Tor
	mu        sync.RWMutex
	running   bool
	circuits  *CircuitManager
	startTime time.Time
}

// NewManager creates a new Tor manager
func NewManager(cfg *config.TorConfig) *Manager {
	return &Manager{
		cfg: cfg,
	}
}

// Start starts the Tor process or connects to existing one
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("tor manager already running")
	}

	log := logger.WithComponent("tor")

	if m.cfg.UseSystemTor {
		log.Info().Msg("connecting to system Tor instance")
		return m.connectToSystemTor(ctx)
	}

	log.Info().Msg("starting embedded Tor instance")
	return m.startEmbeddedTor(ctx)
}

func (m *Manager) startEmbeddedTor(ctx context.Context) error {
	log := logger.WithComponent("tor")

	// Ensure data directory exists
	if err := os.MkdirAll(m.cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Generate torrc WITHOUT ControlPort - bine manages that
	torrc := m.generateTorrcForBine()
	torrcPath := filepath.Join(m.cfg.DataDir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0600); err != nil {
		return fmt.Errorf("failed to write torrc: %w", err)
	}

	log.Debug().Str("torrc", torrc).Msg("generated torrc")

	// Start Tor process using bine
	// Don't set ControlPort - let bine handle it via auto port selection
	startConf := &tor.StartConf{
		ExePath:           m.cfg.Binary,
		DataDir:           m.cfg.DataDir,
		TorrcFile:         torrcPath,
		RetainTempDataDir: true,
		NoAutoSocksPort:   true, // We specify our own SocksPort in torrc
		EnableNetwork:     true,
		DebugWriter:       nil, // Set to os.Stderr for debugging
	}

	log.Info().Msg("starting Tor process...")
	t, err := tor.Start(ctx, startConf)
	if err != nil {
		return fmt.Errorf("failed to start Tor: %w", err)
	}

	m.tor = t
	m.running = true
	m.startTime = time.Now()

	// Initialize circuit manager
	m.circuits = NewCircuitManager(t)

	log.Info().
		Int("control_port", t.ControlPort).
		Str("data_dir", t.DataDir).
		Msg("Tor process started successfully")

	// Save control port to file for new-circuit command
	controlPortFile := filepath.Join(m.cfg.DataDir, "control_port")
	os.WriteFile(controlPortFile, []byte(fmt.Sprintf("%d", t.ControlPort)), 0600)

	// Wait for bootstrap in background
	go func() {
		log.Info().Msg("waiting for Tor to bootstrap...")
		if err := m.waitForBootstrap(ctx); err != nil {
			log.Error().Err(err).Msg("Tor bootstrap failed")
			return
		}
		log.Info().Msg("Tor bootstrapped successfully - ready for traffic!")
	}()

	return nil
}

func (m *Manager) connectToSystemTor(ctx context.Context) error {
	log := logger.WithComponent("tor")

	// For system Tor, we just mark as running and use its SOCKS proxy
	log.Info().Int("socks_port", m.cfg.SOCKSPort).Msg("using system Tor SOCKS proxy")

	m.running = true
	m.startTime = time.Now()

	return nil
}

// generateTorrcForBine generates torrc without ControlPort (bine manages it)
func (m *Manager) generateTorrcForBine() string {
	var torrc string

	torrc += fmt.Sprintf("SocksPort 127.0.0.1:%d\n", m.cfg.SOCKSPort)
	torrc += fmt.Sprintf("TransPort 127.0.0.1:%d\n", m.cfg.TransPort)
	torrc += fmt.Sprintf("DNSPort 127.0.0.1:%d\n", m.cfg.DNSPort)
	// NOTE: Don't set ControlPort here - bine handles it automatically
	torrc += "DataDirectory " + m.cfg.DataDir + "\n"
	torrc += "SafeLogging 0\n"

	// Performance tuning
	torrc += "NumEntryGuards 4\n"
	torrc += "KeepalivePeriod 60\n"
	torrc += "CircuitBuildTimeout 60\n"
	torrc += "LearnCircuitBuildTimeout 0\n"

	// DNS
	torrc += "AutomapHostsOnResolve 1\n"
	torrc += "AutomapHostsSuffixes .onion,.exit\n"

	if m.cfg.ExitNodes != "" {
		torrc += fmt.Sprintf("ExitNodes %s\n", m.cfg.ExitNodes)
	}
	if m.cfg.ExcludeExitNodes != "" {
		torrc += fmt.Sprintf("ExcludeExitNodes %s\n", m.cfg.ExcludeExitNodes)
	}

	return torrc
}

// generateTorrc generates full torrc for external use
func (m *Manager) generateTorrc() string {
	torrc := m.generateTorrcForBine()
	torrc += fmt.Sprintf("ControlPort 127.0.0.1:%d\n", m.cfg.ControlPort)
	torrc += "CookieAuthentication 1\n"
	return torrc
}

func (m *Manager) waitForBootstrap(ctx context.Context) error {
	log := logger.WithComponent("tor")

	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("bootstrap timeout")
		case <-ticker.C:
			if m.tor == nil || m.tor.Control == nil {
				continue
			}

			info, err := m.tor.Control.GetInfo("status/bootstrap-phase")
			if err != nil {
				continue
			}

			for _, entry := range info {
				if progress := parseBootstrapProgress(entry.Val); progress >= 0 {
					log.Debug().Int("progress", progress).Msg("bootstrap progress")
					if progress >= 100 {
						return nil
					}
				}
			}
		}
	}
}

func parseBootstrapProgress(val string) int {
	// Parse "NOTICE BOOTSTRAP PROGRESS=85 ..."
	if len(val) < 10 {
		return -1
	}

	// Simple parsing
	for i := 0; i < len(val)-9; i++ {
		if val[i:i+9] == "PROGRESS=" {
			numStr := ""
			for j := i + 9; j < len(val) && val[j] >= '0' && val[j] <= '9'; j++ {
				numStr += string(val[j])
			}
			if n, err := strconv.Atoi(numStr); err == nil {
				return n
			}
		}
	}
	return -1
}

// Stop stops the Tor process
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	log := logger.WithComponent("tor")
	log.Info().Msg("stopping Tor")

	if m.circuits != nil {
		m.circuits.Stop()
	}

	// Graceful shutdown: signal Tor to shutdown first
	if m.tor != nil && m.tor.Control != nil {
		_ = m.tor.Control.Signal("SHUTDOWN")
		time.Sleep(500 * time.Millisecond)
	}

	if m.tor != nil {
		// Errors during close are expected (broken pipe, process killed)
		// Silently ignore them
		_ = m.tor.Close()
	}

	m.running = false
	return nil
}

// NewIdentity requests a new Tor identity (new circuits)
func (m *Manager) NewIdentity() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.tor == nil || m.tor.Control == nil {
		return fmt.Errorf("not connected to Tor")
	}

	log := logger.WithComponent("tor")
	log.Info().Msg("requesting new identity")

	return m.tor.Control.Signal("NEWNYM")
}

// GetSOCKSAddr returns the SOCKS proxy address
func (m *Manager) GetSOCKSAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.cfg.SOCKSPort)
}

// GetTransportAddr returns the transparent proxy address
func (m *Manager) GetTransportAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.cfg.TransPort)
}

// GetDNSAddr returns the DNS resolver address
func (m *Manager) GetDNSAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", m.cfg.DNSPort)
}

// GetExitIP returns the current exit node IP
func (m *Manager) GetExitIP() (string, error) {
	m.mu.RLock()
	running := m.running
	socksPort := m.cfg.SOCKSPort
	m.mu.RUnlock()

	if !running {
		return "", fmt.Errorf("tor not running")
	}

	// Use curl with SOCKS5 proxy to get exit IP
	socksAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
	cmd := exec.Command("curl", "-s", "--proxy", socksAddr, "--max-time", "15", "https://api.ipify.org")
	output, err := cmd.Output()
	if err != nil {
		// Try alternative endpoint
		cmd = exec.Command("curl", "-s", "--socks5-hostname", fmt.Sprintf("127.0.0.1:%d", socksPort), "--max-time", "15", "https://check.torproject.org/api/ip")
		output, err = cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to get exit IP: %w", err)
		}
		// Parse JSON response {"IsTor":true,"IP":"x.x.x.x"}
		response := string(output)
		if idx := strings.Index(response, "\"IP\":\""); idx != -1 {
			start := idx + 6
			end := strings.Index(response[start:], "\"")
			if end > 0 {
				return response[start : start+end], nil
			}
		}
		return "", fmt.Errorf("could not parse IP from response")
	}

	ip := strings.TrimSpace(string(output))
	if net.ParseIP(ip) != nil {
		return ip, nil
	}

	return "", fmt.Errorf("invalid IP response: %s", ip)
}

// GetStatus returns current Tor status
func (m *Manager) GetStatus() (*Status, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return &Status{Running: false}, nil
	}

	status := &Status{
		Running:   true,
		Uptime:    time.Since(m.startTime),
		SOCKSPort: m.cfg.SOCKSPort,
		TransPort: m.cfg.TransPort,
		DNSPort:   m.cfg.DNSPort,
	}

	// Get circuit info from Tor control
	if m.tor != nil && m.tor.Control != nil {
		// Query actual circuit status
		if circuitInfo, err := m.tor.Control.GetInfo("circuit-status"); err == nil {
			// Count established circuits
			count := 0
			for _, c := range circuitInfo {
				if c.Val != "" {
					count++
				}
			}
			if count > 0 {
				status.ActiveCircuits = count
			}
		}
	} else if m.circuits != nil {
		status.ActiveCircuits = m.circuits.GetCount()
	}

	// Get control port from bine if available
	if m.tor != nil {
		status.ControlPort = m.tor.ControlPort
	}

	// Get bootstrap status
	if m.tor != nil && m.tor.Control != nil {
		info, err := m.tor.Control.GetInfo("status/circuit-established")
		if err == nil && len(info) > 0 {
			status.CircuitEstablished = info[0].Val == "1"
		}
	}

	return status, nil
}

// Status represents Tor daemon status
type Status struct {
	Running            bool
	Uptime             time.Duration
	ControlPort        int
	SOCKSPort          int
	TransPort          int
	DNSPort            int
	ActiveCircuits     int
	CircuitEstablished bool
	ExitIP             string
}

// IsTorInstalled checks if Tor is installed on the system
func IsTorInstalled() bool {
	_, err := exec.LookPath("tor")
	return err == nil
}

// GetTorVersion returns the installed Tor version
func GetTorVersion() (string, error) {
	cmd := exec.Command("tor", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// SetExcludeExitNodes sets exit nodes to avoid based on ML recommendations
// This dynamically updates Tor's configuration via the control port
func (m *Manager) SetExcludeExitNodes(fingerprints []string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.tor == nil || m.tor.Control == nil {
		return fmt.Errorf("not connected to Tor")
	}

	log := logger.WithComponent("tor")

	if len(fingerprints) == 0 {
		// Clear exclusions
		err := m.tor.Control.SetConf(&control.KeyVal{Key: "ExcludeExitNodes", Val: ""})
		if err != nil {
			return fmt.Errorf("failed to clear ExcludeExitNodes: %w", err)
		}
		log.Info().Msg("🧠 ML: cleared exit node exclusions")
		return nil
	}

	// Build exclusion list - Tor accepts IPs or fingerprints
	// Our keys are stored as "exit_<IP>" so we need to extract the IP
	excludeList := ""
	for i, exitKey := range fingerprints {
		if i > 0 {
			excludeList += ","
		}
		// Strip "exit_" prefix if present to get the IP
		ip := exitKey
		if len(exitKey) > 5 && exitKey[:5] == "exit_" {
			ip = exitKey[5:]
		}
		excludeList += ip
	}

	// Apply via control port
	err := m.tor.Control.SetConf(&control.KeyVal{Key: "ExcludeExitNodes", Val: excludeList})
	if err != nil {
		return fmt.Errorf("failed to set ExcludeExitNodes: %w", err)
	}

	log.Info().
		Int("count", len(fingerprints)).
		Str("exits", excludeList).
		Msg("🧠 ML: excluded bad exit nodes")

	return nil
}

// ClearExcludeExitNodes removes all ML-based exit exclusions
func (m *Manager) ClearExcludeExitNodes() error {
	return m.SetExcludeExitNodes(nil)
}
