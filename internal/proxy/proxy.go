// Package proxy provides the main proxy controller for TorForge
package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jery0843/torforge/internal/ai"
	"github.com/jery0843/torforge/internal/api"
	"github.com/jery0843/torforge/internal/bypass"
	"github.com/jery0843/torforge/internal/netfilter"
	"github.com/jery0843/torforge/internal/security"
	"github.com/jery0843/torforge/internal/tor"
	"github.com/jery0843/torforge/pkg/config"
	"github.com/jery0843/torforge/pkg/logger"
)

// Proxy is the main controller for TorForge
type Proxy struct {
	cfg         *config.Config
	torMgr      *tor.Manager
	iptables    *netfilter.IPTablesManager
	dnsResolver *netfilter.DNSResolver
	bypassEng   *bypass.Engine
	apiServer   *api.Server

	// AI modules
	circuitAI   *ai.SmartCircuitSelector
	splitTunnel *ai.SplitTunnelAI

	// Security modules
	quantumLayer *security.QuantumResistantLayer

	mu        sync.RWMutex
	running   bool
	startTime time.Time
	ctx       context.Context
	cancel    context.CancelFunc

	// Stats
	bytesSent    int64
	bytesRecv    int64
	dnsQueries   int64
	blockedLeaks int
}

// New creates a new Proxy instance
func New(cfg *config.Config) (*Proxy, error) {
	log := logger.WithComponent("proxy")

	// Validate requirements
	if !tor.IsTorInstalled() {
		return nil, fmt.Errorf("tor is not installed. Please install tor first")
	}

	if err := netfilter.CheckRequirements(); err != nil {
		return nil, fmt.Errorf("iptables requirements not met: %w", err)
	}

	// Create Tor manager
	torMgr := tor.NewManager(&cfg.Tor)

	// Create iptables manager
	iptables, err := netfilter.NewIPTablesManager(&cfg.Proxy, &cfg.Tor, &cfg.Bypass, &cfg.Security)
	if err != nil {
		return nil, fmt.Errorf("failed to create iptables manager: %w", err)
	}

	// Create DNS resolver
	dnsResolver := netfilter.NewDNSResolver(&cfg.Tor, &cfg.Bypass)

	// Create bypass engine
	bypassEng, err := bypass.NewEngine(&cfg.Bypass)
	if err != nil {
		log.Warn().Err(err).Msg("failed to create bypass engine, continuing without")
	}

	// Initialize AI modules
	aiDataDir := "/var/lib/torforge/ai"
	circuitAI := ai.NewSmartCircuitSelector(aiDataDir)
	splitTunnel := ai.NewSplitTunnelAI(aiDataDir)
	log.Info().Msg("AI modules initialized")

	p := &Proxy{
		cfg:         cfg,
		torMgr:      torMgr,
		iptables:    iptables,
		dnsResolver: dnsResolver,
		bypassEng:   bypassEng,
		circuitAI:   circuitAI,
		splitTunnel: splitTunnel,
	}

	// Create API server if enabled
	if cfg.API.Enabled {
		p.apiServer = api.NewServer(&cfg.API, &api.Handlers{
			OnNewCircuit:   p.NewCircuit,
			OnGetStatus:    p.getAPIStatus,
			OnGetCircuits:  p.getAPICircuits,
			OnAddBypass:    p.addBypassRule,
			OnRemoveBypass: p.removeBypassRule,
			OnStop:         p.Stop,
		})
	}

	return p, nil
}

// Start starts the transparent proxy
func (p *Proxy) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("proxy already running")
	}

	log := logger.WithComponent("proxy")
	log.Info().Msg("starting TorForge proxy")

	p.ctx, p.cancel = context.WithCancel(ctx)

	// Step 1: Start Tor process (but don't wait for full bootstrap yet)
	log.Info().Msg("starting Tor")
	if err := p.torMgr.Start(p.ctx); err != nil {
		return fmt.Errorf("failed to start Tor: %w", err)
	}

	// Step 2: Apply iptables rules IMMEDIATELY after Tor starts
	// This ensures traffic is routed even during bootstrap
	log.Info().Msg("applying iptables rules")
	if err := p.iptables.Apply(); err != nil {
		p.torMgr.Stop()
		return fmt.Errorf("failed to apply iptables: %w", err)
	}

	// Step 3: Start API server if enabled
	if p.apiServer != nil {
		log.Info().Msg("starting API server")
		if err := p.apiServer.Start(); err != nil {
			log.Warn().Err(err).Msg("failed to start API server")
		}
	}

	p.running = true
	p.startTime = time.Now()

	// Step 4: Start AI data collection
	go p.collectAIData()

	// Log success - Tor may still be bootstrapping
	log.Info().Msg("proxy active - iptables rules applied")
	log.Info().Msg("Tor is bootstrapping in background (traffic will route once connected)")

	logger.Audit("proxy").
		Str("action", "start").
		Int("socks_port", p.cfg.Tor.SOCKSPort).
		Int("trans_port", p.cfg.Tor.TransPort).
		Int("dns_port", p.cfg.Tor.DNSPort).
		Msg("TorForge started")

	return nil
}

// Stop stops the transparent proxy
func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	log := logger.WithComponent("proxy")
	log.Info().Msg("stopping TorForge proxy")

	var lastErr error

	// Cancel context
	if p.cancel != nil {
		p.cancel()
	}

	// Stop API server
	if p.apiServer != nil {
		if err := p.apiServer.Stop(); err != nil {
			log.Warn().Err(err).Msg("error stopping API server")
			lastErr = err
		}
	}

	// Rollback iptables
	if err := p.iptables.Rollback(); err != nil {
		log.Error().Err(err).Msg("error rolling back iptables")
		lastErr = err
	}

	// Stop DNS resolver
	if p.dnsResolver != nil {
		p.dnsResolver.Stop()
	}

	// Stop Tor
	if err := p.torMgr.Stop(); err != nil {
		log.Error().Err(err).Msg("error stopping Tor")
		lastErr = err
	}

	p.running = false

	logger.Audit("proxy").
		Str("action", "stop").
		Dur("uptime", time.Since(p.startTime)).
		Msg("TorForge stopped")

	log.Info().Msg("proxy stopped")
	return lastErr
}

// Cleanup cleans up any leftover state (for crash recovery)
func (p *Proxy) Cleanup() error {
	log := logger.WithComponent("proxy")
	log.Info().Msg("cleaning up")

	// Try to rollback iptables even if not running
	if err := p.iptables.Rollback(); err != nil {
		log.Warn().Err(err).Msg("iptables rollback failed")
	}

	return nil
}

// NewCircuit requests a new Tor identity
func (p *Proxy) NewCircuit() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if !p.running {
		return fmt.Errorf("proxy not running")
	}

	log := logger.WithComponent("proxy")
	log.Info().Msg("requesting new circuit")

	if err := p.torMgr.NewIdentity(); err != nil {
		return err
	}

	logger.Audit("circuit").Str("action", "new_identity").Msg("")
	return nil
}

// GetStatus returns the current proxy status
func (p *Proxy) GetStatus() (*Status, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	status := &Status{
		Running: p.running,
	}

	if !p.running {
		return status, nil
	}

	status.Uptime = time.Since(p.startTime)
	status.IPTablesActive = p.iptables.IsActive()

	// Get Tor status
	torStatus, err := p.torMgr.GetStatus()
	if err == nil {
		status.TorRunning = torStatus.Running
		status.ActiveCircuits = torStatus.ActiveCircuits
		status.CircuitEstablished = torStatus.CircuitEstablished
	}

	// Get exit IP (may take a moment)
	if exitIP, err := p.torMgr.GetExitIP(); err == nil {
		status.ExitIP = exitIP
	}

	status.BytesSent = p.bytesSent
	status.BytesRecv = p.bytesRecv
	status.DNSQueries = p.dnsQueries
	status.BlockedLeaks = p.blockedLeaks

	return status, nil
}

// Status represents the current proxy status
type Status struct {
	Running            bool
	Uptime             time.Duration
	TorRunning         bool
	IPTablesActive     bool
	ActiveCircuits     int
	CircuitEstablished bool
	ExitIP             string
	BytesSent          int64
	BytesRecv          int64
	DNSQueries         int64
	BlockedLeaks       int
}

// API handler implementations
func (p *Proxy) getAPIStatus() (*api.StatusResponse, error) {
	status, err := p.GetStatus()
	if err != nil {
		return nil, err
	}

	return &api.StatusResponse{
		Running:        status.Running,
		Uptime:         status.Uptime.String(),
		UptimeSeconds:  int64(status.Uptime.Seconds()),
		ExitIP:         status.ExitIP,
		ActiveCircuits: status.ActiveCircuits,
		BytesSent:      status.BytesSent,
		BytesRecv:      status.BytesRecv,
		DNSQueries:     status.DNSQueries,
		Version:        "1.0.0",
	}, nil
}

func (p *Proxy) getAPICircuits() ([]api.CircuitInfo, error) {
	// Get circuits from Tor manager
	// Simplified implementation
	return []api.CircuitInfo{}, nil
}

func (p *Proxy) addBypassRule(req api.BypassRuleRequest) error {
	if p.bypassEng == nil {
		return fmt.Errorf("bypass engine not initialized")
	}

	rule := bypass.Rule{
		Name:    req.Name,
		Type:    bypass.RuleType(req.Type),
		Pattern: req.Pattern,
		Action:  bypass.Action(req.Action),
	}

	return p.bypassEng.AddRule(rule)
}

func (p *Proxy) removeBypassRule(name string) error {
	if p.bypassEng == nil {
		return fmt.Errorf("bypass engine not initialized")
	}

	if !p.bypassEng.RemoveRule(name) {
		return fmt.Errorf("rule not found: %s", name)
	}
	return nil
}

// IsRunning returns whether the proxy is running
func (p *Proxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// GetBypassEngine returns the bypass engine
func (p *Proxy) GetBypassEngine() *bypass.Engine {
	return p.bypassEng
}

// GetTorManager returns the Tor manager
func (p *Proxy) GetTorManager() *tor.Manager {
	return p.torMgr
}

// GetCircuitAI returns the smart circuit selector
func (p *Proxy) GetCircuitAI() *ai.SmartCircuitSelector {
	return p.circuitAI
}

// GetSplitTunnelAI returns the split-tunnel AI
func (p *Proxy) GetSplitTunnelAI() *ai.SplitTunnelAI {
	return p.splitTunnel
}

// collectAIData periodically collects circuit performance data for AI learning
func (p *Proxy) collectAIData() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.mu.RLock()
			running := p.running
			p.mu.RUnlock()

			if !running {
				return
			}

			// Measure exit node performance
			p.measureCircuitPerformance()
		}
	}
}

// measureCircuitPerformance measures and records current circuit performance
func (p *Proxy) measureCircuitPerformance() {
	log := logger.WithComponent("ai")

	if p.circuitAI == nil || p.torMgr == nil {
		return
	}

	// Get current status
	status, err := p.torMgr.GetStatus()
	if err != nil || !status.Running {
		return
	}

	// Measure latency to a test endpoint through Tor
	startTime := time.Now()
	exitIP, err := p.torMgr.GetExitIP()
	latencyMs := float64(time.Since(startTime).Milliseconds())

	if err != nil || exitIP == "" {
		return
	}

	// Estimate bandwidth (simplified - use latency as proxy)
	bandwidthKbps := 10000.0 / (latencyMs + 1) * 100 // Rough estimate

	// Record to AI
	exitFingerprint := fmt.Sprintf("exit_%s", exitIP)
	p.circuitAI.RecordCircuitPerformance(
		exitFingerprint,
		"unknown", // Country - would need GeoIP lookup
		"general", // Destination
		latencyMs,
		bandwidthKbps,
		true, // Success
	)

	log.Debug().
		Str("exit_ip", exitIP).
		Float64("latency_ms", latencyMs).
		Float64("bandwidth_kbps", bandwidthKbps).
		Msg("recorded circuit performance")
}

// EnableQuantumLayer enables post-quantum encryption
func (p *Proxy) EnableQuantumLayer() error {
	log := logger.WithComponent("quantum")

	cfg := &security.PostQuantumConfig{
		Enabled:   true,
		Algorithm: "kyber768",
	}

	q, err := security.NewQuantumResistantLayer(cfg)
	if err != nil {
		return err
	}

	// Run self-test
	passed, err := q.TestEncryption()
	if err != nil {
		return fmt.Errorf("quantum self-test failed: %w", err)
	}
	if !passed {
		return fmt.Errorf("quantum encryption verification failed")
	}

	p.quantumLayer = q
	log.Info().Msg("🔐 Post-quantum encryption layer ACTIVE and VERIFIED")

	return nil
}

// GetQuantumStatus returns the quantum layer status
func (p *Proxy) GetQuantumStatus() map[string]interface{} {
	if p.quantumLayer == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	return p.quantumLayer.GetStatus()
}

// EncryptData encrypts data with quantum layer if enabled
func (p *Proxy) EncryptData(data []byte) ([]byte, error) {
	if p.quantumLayer == nil || !p.quantumLayer.IsEnabled() {
		return data, nil
	}
	return p.quantumLayer.Encrypt(data)
}

// DecryptData decrypts data with quantum layer if enabled
func (p *Proxy) DecryptData(data []byte) ([]byte, error) {
	if p.quantumLayer == nil || !p.quantumLayer.IsEnabled() {
		return data, nil
	}
	return p.quantumLayer.Decrypt(data)
}
