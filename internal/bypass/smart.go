// Package bypass provides smart pattern-based bypass engine
package bypass

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/jery0843/torforge/pkg/logger"
)

// PatternType represents the type of traffic pattern
type PatternType string

const (
	PatternStreaming PatternType = "streaming"
	PatternGaming    PatternType = "gaming"
	PatternVoIP      PatternType = "voip"
	PatternDownload  PatternType = "download"
	PatternBrowsing  PatternType = "browsing"
	PatternUnknown   PatternType = "unknown"
)

// TrafficPattern represents learned traffic patterns
type TrafficPattern struct {
	Domain          string      `json:"domain"`
	Type            PatternType `json:"type"`
	AvgPacketSize   int         `json:"avg_packet_size"`
	PacketsPerSec   float64     `json:"packets_per_sec"`
	ConnectionCount int         `json:"connection_count"`
	BypassScore     float64     `json:"bypass_score"` // 0-1, higher = should bypass
	LastSeen        time.Time   `json:"last_seen"`
	Confidence      float64     `json:"confidence"` // 0-1
}

// SmartBypass provides intelligent, pattern-based bypass decisions
type SmartBypass struct {
	patterns     map[string]*TrafficPattern
	stats        map[string]*ConnectionStats
	mu           sync.RWMutex
	dataDir      string
	patternsFile string

	// Known patterns for quick matching
	streamingDomains *regexp.Regexp
	gamingDomains    *regexp.Regexp
	voipDomains      *regexp.Regexp
	localDomains     *regexp.Regexp

	// Signature-based detection
	appSignatures map[string]AppSignature
}

// ConnectionStats tracks connection statistics
type ConnectionStats struct {
	Domain       string
	TotalBytes   int64
	TotalPackets int64
	Connections  int
	FirstSeen    time.Time
	LastSeen     time.Time
	AvgLatency   time.Duration
}

// AppSignature represents application traffic signatures
type AppSignature struct {
	Name          string
	Protocols     []string
	Ports         []int
	DomainPattern *regexp.Regexp
	PacketPattern []byte
	ShouldBypass  bool
}

// NewSmartBypass creates a new smart bypass engine
func NewSmartBypass(dataDir string) (*SmartBypass, error) {
	sb := &SmartBypass{
		patterns:      make(map[string]*TrafficPattern),
		stats:         make(map[string]*ConnectionStats),
		dataDir:       dataDir,
		patternsFile:  filepath.Join(dataDir, "patterns.json"),
		appSignatures: make(map[string]AppSignature),
	}

	// Compile known domain patterns
	sb.streamingDomains = regexp.MustCompile(`(?i)(netflix|youtube|twitch|spotify|hulu|disney|prime|video|stream)`)
	sb.gamingDomains = regexp.MustCompile(`(?i)(steam|valve|blizzard|riot|epicgames|ea\.com|ubisoft|xbox|playstation)`)
	sb.voipDomains = regexp.MustCompile(`(?i)(zoom|teams|meet|discord|skype|webex|slack|signal)`)
	sb.localDomains = regexp.MustCompile(`(?i)(\.local$|\.lan$|\.home$|\.internal$|localhost)`)

	// Initialize known app signatures
	sb.initSignatures()

	// Load saved patterns
	sb.loadPatterns()

	return sb, nil
}

// initSignatures initializes known application signatures
func (sb *SmartBypass) initSignatures() {
	sb.appSignatures = map[string]AppSignature{
		"steam": {
			Name:          "Steam",
			Protocols:     []string{"tcp", "udp"},
			Ports:         []int{27015, 27036, 27037},
			DomainPattern: regexp.MustCompile(`(?i)steam|valve`),
			ShouldBypass:  true, // Gaming needs low latency
		},
		"discord": {
			Name:          "Discord",
			Protocols:     []string{"udp"},
			Ports:         []int{50000, 50001, 50002},
			DomainPattern: regexp.MustCompile(`(?i)discord`),
			ShouldBypass:  true, // VoIP needs low latency
		},
		"spotify": {
			Name:          "Spotify",
			Protocols:     []string{"tcp"},
			Ports:         []int{4070, 443},
			DomainPattern: regexp.MustCompile(`(?i)spotify|scdn`),
			ShouldBypass:  false, // Streaming can work through Tor
		},
		"zoom": {
			Name:          "Zoom",
			Protocols:     []string{"udp"},
			Ports:         []int{8801, 8802},
			DomainPattern: regexp.MustCompile(`(?i)zoom`),
			ShouldBypass:  true, // Video calls need low latency
		},
	}
}

// ShouldBypass returns whether traffic should bypass Tor
func (sb *SmartBypass) ShouldBypass(domain string, destIP net.IP, port int, protocol string) bool {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	log := logger.WithComponent("smart-bypass")

	// Check 1: Local domains always bypass
	if sb.localDomains.MatchString(domain) {
		log.Debug().Str("domain", domain).Msg("bypassing local domain")
		return true
	}

	// Check 2: Check app signatures
	for name, sig := range sb.appSignatures {
		if sb.matchesSignature(domain, port, protocol, sig) {
			log.Debug().Str("app", name).Str("domain", domain).Bool("bypass", sig.ShouldBypass).Msg("matched signature")
			return sig.ShouldBypass
		}
	}

	// Check 3: Pattern-based detection
	patternType := sb.detectPatternType(domain)
	switch patternType {
	case PatternGaming, PatternVoIP:
		log.Debug().Str("domain", domain).Str("type", string(patternType)).Msg("bypassing latency-sensitive")
		return true
	case PatternStreaming:
		// Streaming can work through Tor, don't bypass by default
		return false
	}

	// Check 4: Learned patterns
	if pattern, ok := sb.patterns[domain]; ok {
		if pattern.BypassScore > 0.7 && pattern.Confidence > 0.5 {
			log.Debug().Str("domain", domain).Float64("score", pattern.BypassScore).Msg("learned bypass")
			return true
		}
	}

	return false
}

// matchesSignature checks if traffic matches an app signature
func (sb *SmartBypass) matchesSignature(domain string, port int, protocol string, sig AppSignature) bool {
	// Check domain
	if sig.DomainPattern != nil && sig.DomainPattern.MatchString(domain) {
		return true
	}

	// Check port
	for _, p := range sig.Ports {
		if p == port {
			return true
		}
	}

	return false
}

// detectPatternType detects the type of traffic based on domain
func (sb *SmartBypass) detectPatternType(domain string) PatternType {
	if sb.streamingDomains.MatchString(domain) {
		return PatternStreaming
	}
	if sb.gamingDomains.MatchString(domain) {
		return PatternGaming
	}
	if sb.voipDomains.MatchString(domain) {
		return PatternVoIP
	}
	return PatternUnknown
}

// RecordConnection records a connection for learning
func (sb *SmartBypass) RecordConnection(domain string, bytes int64, latency time.Duration) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	now := time.Now()

	stats, ok := sb.stats[domain]
	if !ok {
		stats = &ConnectionStats{
			Domain:    domain,
			FirstSeen: now,
		}
		sb.stats[domain] = stats
	}

	stats.TotalBytes += bytes
	stats.TotalPackets++
	stats.Connections++
	stats.LastSeen = now

	// Update average latency
	if stats.AvgLatency == 0 {
		stats.AvgLatency = latency
	} else {
		stats.AvgLatency = (stats.AvgLatency + latency) / 2
	}

	// Update pattern
	sb.updatePattern(stats)
}

// updatePattern updates learned patterns based on stats
func (sb *SmartBypass) updatePattern(stats *ConnectionStats) {
	pattern, ok := sb.patterns[stats.Domain]
	if !ok {
		pattern = &TrafficPattern{
			Domain: stats.Domain,
		}
		sb.patterns[stats.Domain] = pattern
	}

	pattern.ConnectionCount = stats.Connections
	pattern.LastSeen = stats.LastSeen
	pattern.Type = sb.detectPatternType(stats.Domain)

	// Calculate bypass score based on latency sensitivity
	if stats.AvgLatency > 0 {
		// High latency connections should bypass
		if stats.AvgLatency > 500*time.Millisecond {
			pattern.BypassScore = 0.8
		} else if stats.AvgLatency > 200*time.Millisecond {
			pattern.BypassScore = 0.5
		} else {
			pattern.BypassScore = 0.2
		}
	}

	// Update confidence based on sample size
	if stats.Connections > 100 {
		pattern.Confidence = 0.9
	} else if stats.Connections > 10 {
		pattern.Confidence = 0.6
	} else {
		pattern.Confidence = 0.3
	}
}

// SavePatterns saves learned patterns to disk
func (sb *SmartBypass) SavePatterns() error {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	data, err := json.MarshalIndent(sb.patterns, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sb.patternsFile, data, 0600)
}

// loadPatterns loads patterns from disk
func (sb *SmartBypass) loadPatterns() {
	data, err := os.ReadFile(sb.patternsFile)
	if err != nil {
		return // No saved patterns
	}

	json.Unmarshal(data, &sb.patterns)
}

// GetTopDomains returns top domains by connection count
func (sb *SmartBypass) GetTopDomains(n int) []TrafficPattern {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	patterns := make([]TrafficPattern, 0, len(sb.patterns))
	for _, p := range sb.patterns {
		patterns = append(patterns, *p)
	}

	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].ConnectionCount > patterns[j].ConnectionCount
	})

	if len(patterns) > n {
		patterns = patterns[:n]
	}

	return patterns
}

// GetBypassSuggestions returns domains that should probably bypass
func (sb *SmartBypass) GetBypassSuggestions() []string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	var suggestions []string
	for domain, pattern := range sb.patterns {
		if pattern.BypassScore > 0.5 && pattern.Confidence > 0.4 {
			suggestions = append(suggestions, domain)
		}
	}

	return suggestions
}

// AddManualBypass adds a manual bypass rule
func (sb *SmartBypass) AddManualBypass(domain string) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	pattern, ok := sb.patterns[domain]
	if !ok {
		pattern = &TrafficPattern{
			Domain: domain,
		}
		sb.patterns[domain] = pattern
	}

	pattern.BypassScore = 1.0
	pattern.Confidence = 1.0
}

// ClearPatterns clears all learned patterns
func (sb *SmartBypass) ClearPatterns() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	sb.patterns = make(map[string]*TrafficPattern)
	sb.stats = make(map[string]*ConnectionStats)
	os.Remove(sb.patternsFile)
}
