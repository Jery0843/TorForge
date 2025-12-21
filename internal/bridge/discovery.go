// Package bridge provides Tor bridge discovery and management
package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
)

// BridgeType represents the type of Tor bridge
type BridgeType string

const (
	BridgeTypeObfs4     BridgeType = "obfs4"
	BridgeTypeSnowflake BridgeType = "snowflake"
	BridgeTypeMeek      BridgeType = "meek-azure"
	BridgeTypeVanilla   BridgeType = "vanilla"
)

// Bridge represents a Tor bridge
type Bridge struct {
	Type        BridgeType `json:"type"`
	Address     string     `json:"address"`
	Fingerprint string     `json:"fingerprint"`
	Params      string     `json:"params"` // Transport-specific parameters
	LastTested  time.Time  `json:"last_tested"`
	Working     bool       `json:"working"`
	Latency     int        `json:"latency_ms"`
}

// BridgeDiscovery handles automatic bridge discovery and testing
type BridgeDiscovery struct {
	mu sync.RWMutex

	// Known bridges
	bridges []Bridge

	// Configuration
	dataDir        string
	testTimeout    time.Duration
	maxBridges     int
	preferredTypes []BridgeType

	// Cached working bridges
	workingBridges []Bridge

	// HTTP client for fetching bridges
	httpClient *http.Client
}

// NewBridgeDiscovery creates a new bridge discovery instance
func NewBridgeDiscovery(dataDir string) *BridgeDiscovery {
	bd := &BridgeDiscovery{
		bridges:        []Bridge{},
		workingBridges: []Bridge{},
		dataDir:        dataDir,
		testTimeout:    30 * time.Second,
		maxBridges:     10,
		preferredTypes: []BridgeType{BridgeTypeObfs4, BridgeTypeSnowflake},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Load cached bridges
	bd.loadBridges()

	// Add built-in fallback bridges
	bd.addBuiltinBridges()

	return bd
}

// addBuiltinBridges adds some well-known public bridges as fallback
func (bd *BridgeDiscovery) addBuiltinBridges() {
	// Public bridges from the Tor Project (call DiscoverBridges() to fetch latest)
	builtinBridges := []Bridge{
		{
			Type:    BridgeTypeSnowflake,
			Address: "snowflake 192.0.2.3:80",
			Params:  "url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478",
		},
		{
			Type:    BridgeTypeMeek,
			Address: "meek_lite 0.0.2.0:2",
			Params:  "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com",
		},
	}

	for _, b := range builtinBridges {
		bd.addBridge(b)
	}
}

// DetectCensorship checks if Tor is being blocked
func (bd *BridgeDiscovery) DetectCensorship(ctx context.Context) (bool, string) {
	log := logger.WithComponent("bridge")
	log.Info().Msg("detecting censorship...")

	// Test 1: Try to connect to Tor directory authorities
	dirAuthorities := []string{
		"128.31.0.39:9131",   // moria1
		"86.59.21.38:443",    // tor26
		"194.109.206.212:80", // dizum
	}

	blocked := 0
	for _, addr := range dirAuthorities {
		conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			blocked++
			continue
		}
		conn.Close()
	}

	if blocked >= 2 {
		log.Warn().Int("blocked", blocked).Msg("censorship detected - directory authorities blocked")
		return true, "directory_authorities_blocked"
	}

	// Test 2: Try to fetch Tor consensus
	resp, err := bd.httpClient.Get("https://consensus-health.torproject.org/")
	if err != nil {
		log.Warn().Err(err).Msg("censorship detected - tor project blocked")
		return true, "torproject_blocked"
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return true, "torproject_filtered"
	}

	log.Info().Msg("no censorship detected")
	return false, ""
}

// DiscoverBridges attempts to discover working bridges
func (bd *BridgeDiscovery) DiscoverBridges(ctx context.Context) ([]Bridge, error) {
	log := logger.WithComponent("bridge")
	log.Info().Msg("discovering bridges...")

	var discovered []Bridge

	// Method 1: Fetch from bridges.torproject.org (via API)
	apiBridges, err := bd.fetchFromMoat(ctx)
	if err == nil {
		discovered = append(discovered, apiBridges...)
		log.Info().Int("count", len(apiBridges)).Msg("fetched bridges from Moat API")
	}

	// Method 2: Use built-in Snowflake bridges (always available)
	for _, b := range bd.bridges {
		if b.Type == BridgeTypeSnowflake || b.Type == BridgeTypeMeek {
			discovered = append(discovered, b)
		}
	}

	// Test discovered bridges
	working := bd.testBridges(ctx, discovered)

	bd.mu.Lock()
	bd.workingBridges = working
	bd.mu.Unlock()

	// Save for future use
	bd.saveBridges()

	log.Info().Int("working", len(working)).Msg("bridge discovery complete")
	return working, nil
}

// fetchFromMoat fetches bridges from Tor's Moat API
func (bd *BridgeDiscovery) fetchFromMoat(ctx context.Context) ([]Bridge, error) {
	// Moat API endpoint
	moatURL := "https://bridges.torproject.org/moat/circumvention/builtin"

	req, err := http.NewRequestWithContext(ctx, "GET", moatURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := bd.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("moat returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse response
	var moatResp struct {
		Bridges []string `json:"bridges"`
	}
	if err := json.Unmarshal(body, &moatResp); err != nil {
		// Try parsing as plain text (one bridge per line)
		return bd.parseBridgeLines(string(body)), nil
	}

	var bridges []Bridge
	for _, line := range moatResp.Bridges {
		if b := bd.parseBridgeLine(line); b != nil {
			bridges = append(bridges, *b)
		}
	}

	return bridges, nil
}

// parseBridgeLines parses multiple bridge lines
func (bd *BridgeDiscovery) parseBridgeLines(text string) []Bridge {
	var bridges []Bridge
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if b := bd.parseBridgeLine(line); b != nil {
			bridges = append(bridges, *b)
		}
	}
	return bridges
}

// parseBridgeLine parses a single bridge line
func (bd *BridgeDiscovery) parseBridgeLine(line string) *Bridge {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	// Handle "Bridge <line>" prefix
	line = strings.TrimPrefix(line, "Bridge ")

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	b := &Bridge{}

	// Check if first part is transport type
	switch parts[0] {
	case "obfs4":
		b.Type = BridgeTypeObfs4
		b.Address = parts[1]
		if len(parts) > 2 {
			b.Fingerprint = parts[2]
		}
		if len(parts) > 3 {
			b.Params = strings.Join(parts[3:], " ")
		}
	case "snowflake":
		b.Type = BridgeTypeSnowflake
		b.Address = strings.Join(parts[1:], " ")
	case "meek_lite", "meek":
		b.Type = BridgeTypeMeek
		b.Address = strings.Join(parts[1:], " ")
	default:
		// Vanilla bridge (IP:port fingerprint)
		b.Type = BridgeTypeVanilla
		b.Address = parts[0]
		if len(parts) > 1 {
			b.Fingerprint = parts[1]
		}
	}

	return b
}

// testBridges tests bridges for connectivity
func (bd *BridgeDiscovery) testBridges(ctx context.Context, bridges []Bridge) []Bridge {
	log := logger.WithComponent("bridge")
	var working []Bridge

	for _, b := range bridges {
		// Skip testing Snowflake and Meek (they use different protocols)
		if b.Type == BridgeTypeSnowflake || b.Type == BridgeTypeMeek {
			b.Working = true
			working = append(working, b)
			continue
		}

		// Test TCP connection for obfs4 and vanilla bridges
		addr := b.Address
		if idx := strings.Index(addr, " "); idx > 0 {
			addr = addr[:idx]
		}

		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, bd.testTimeout)
		if err != nil {
			log.Debug().Str("bridge", addr).Err(err).Msg("bridge test failed")
			continue
		}
		conn.Close()

		b.Latency = int(time.Since(start).Milliseconds())
		b.Working = true
		b.LastTested = time.Now()
		working = append(working, b)

		log.Debug().Str("bridge", addr).Int("latency", b.Latency).Msg("bridge test passed")
	}

	return working
}

// GetWorkingBridges returns currently working bridges
func (bd *BridgeDiscovery) GetWorkingBridges() []Bridge {
	bd.mu.RLock()
	defer bd.mu.RUnlock()
	return bd.workingBridges
}

// GetBridgeLines returns bridge lines for Tor configuration
func (bd *BridgeDiscovery) GetBridgeLines() []string {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	var lines []string
	for _, b := range bd.workingBridges {
		line := ""
		switch b.Type {
		case BridgeTypeObfs4:
			line = fmt.Sprintf("obfs4 %s %s %s", b.Address, b.Fingerprint, b.Params)
		case BridgeTypeSnowflake:
			line = fmt.Sprintf("snowflake %s %s", b.Address, b.Params)
		case BridgeTypeMeek:
			line = fmt.Sprintf("meek_lite %s %s", b.Address, b.Params)
		case BridgeTypeVanilla:
			line = fmt.Sprintf("%s %s", b.Address, b.Fingerprint)
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	return lines
}

// addBridge adds a bridge to the list
func (bd *BridgeDiscovery) addBridge(b Bridge) {
	bd.mu.Lock()
	defer bd.mu.Unlock()

	// Check for duplicates
	for _, existing := range bd.bridges {
		if existing.Address == b.Address {
			return
		}
	}

	bd.bridges = append(bd.bridges, b)
}

// loadBridges loads cached bridges from disk
func (bd *BridgeDiscovery) loadBridges() {
	path := filepath.Join(bd.dataDir, "bridges.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	json.Unmarshal(data, &bd.bridges)
}

// saveBridges saves bridges to disk
func (bd *BridgeDiscovery) saveBridges() {
	bd.mu.RLock()
	defer bd.mu.RUnlock()

	os.MkdirAll(bd.dataDir, 0700)
	path := filepath.Join(bd.dataDir, "bridges.json")
	data, _ := json.MarshalIndent(bd.bridges, "", "  ")
	os.WriteFile(path, data, 0600)
}

// AutoDiscover performs automatic bridge discovery if censorship is detected
func (bd *BridgeDiscovery) AutoDiscover(ctx context.Context) (bool, []Bridge, error) {
	log := logger.WithComponent("bridge")

	// Check for censorship
	censored, reason := bd.DetectCensorship(ctx)
	if !censored {
		log.Info().Msg("no censorship detected, bridges not needed")
		return false, nil, nil
	}

	log.Warn().Str("reason", reason).Msg("censorship detected, discovering bridges")

	// Discover working bridges
	bridges, err := bd.DiscoverBridges(ctx)
	if err != nil {
		return true, nil, err
	}

	if len(bridges) == 0 {
		return true, nil, fmt.Errorf("no working bridges found")
	}

	return true, bridges, nil
}
