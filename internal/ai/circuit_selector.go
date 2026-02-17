// Package ai implements exit node quality prediction using a lightweight neural network.
//
// Design rationale: We use a simple 3-layer MLP (6→16→8→1) rather than heavyweight
// ML frameworks because: (1) the prediction problem is low-dimensional, (2) we need
// sub-millisecond inference for real-time circuit selection, and (3) zero external
// dependencies reduce attack surface for a security tool.
//
// The model learns from observed latency/bandwidth samples and excludes consistently
// poor exit nodes. A TTL-based re-evaluation (1 hour) prevents permanent exclusions,
// allowing nodes to recover after transient load issues.
package ai

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jery0843/torforge/internal/ai/ml"
	"github.com/jery0843/torforge/pkg/logger"
)

// CircuitPerformance stores performance metrics for a circuit/exit
type CircuitPerformance struct {
	ExitFingerprint string    `json:"exit_fingerprint"`
	ExitCountry     string    `json:"exit_country"`
	AvgLatency      float64   `json:"avg_latency_ms"`
	AvgBandwidth    float64   `json:"avg_bandwidth_kbps"`
	SuccessRate     float64   `json:"success_rate"`
	SampleCount     int       `json:"sample_count"`
	LastUpdated     time.Time `json:"last_updated"`

	// Per-destination performance
	DestinationStats map[string]*DestinationPerf `json:"destination_stats"`
}

// DestinationPerf stores performance for specific destinations
type DestinationPerf struct {
	Domain       string  `json:"domain"`
	AvgLatency   float64 `json:"avg_latency_ms"`
	AvgBandwidth float64 `json:"avg_bandwidth_kbps"`
	SampleCount  int     `json:"sample_count"`
}

// SmartCircuitSelector uses neural network to select optimal circuits
type SmartCircuitSelector struct {
	mu sync.RWMutex

	// Historical performance data
	exitPerformance map[string]*CircuitPerformance

	// Neural network model for quality prediction
	mlModel   *ml.QualityModel
	mlEnabled bool

	// Fallback prediction weights (used when ML not ready)
	latencyWeight   float64
	bandwidthWeight float64
	successWeight   float64
	recencyWeight   float64

	// Configuration
	dataDir      string
	learningRate float64
	decayFactor  float64
	minSamples   int

	// Exclusion TTL tracking
	exclusionStartTime time.Time
	cachedAvoidExits   []string
	exclusionTTL       time.Duration

	// Real-time metrics
	currentCircuits map[string]*LiveCircuitMetrics
}

// LiveCircuitMetrics tracks real-time performance
type LiveCircuitMetrics struct {
	CircuitID    string
	ExitNode     string
	StartTime    time.Time
	BytesSent    int64
	BytesRecv    int64
	RequestCount int
	ErrorCount   int
	AvgRTT       float64
}

// NewSmartCircuitSelector creates a new AI circuit selector with neural network
func NewSmartCircuitSelector(dataDir string) *SmartCircuitSelector {
	log := logger.WithComponent("ai")

	s := &SmartCircuitSelector{
		exitPerformance: make(map[string]*CircuitPerformance),
		currentCircuits: make(map[string]*LiveCircuitMetrics),
		dataDir:         dataDir,

		// Fallback weights (used when ML not available)
		latencyWeight:   0.35,
		bandwidthWeight: 0.30,
		successWeight:   0.25,
		recencyWeight:   0.10,

		learningRate: 0.1,
		decayFactor:  0.95,
		minSamples:   5,

		// Re-evaluate excluded exits after 1 hour.
		// Why 1 hour? Tor exit node performance fluctuates with load.
		// Too short = thrashing (re-test before conditions stabilize).
		// Too long = miss genuinely recovered nodes.
		// 1 hour balances stability vs adaptability based on empirical observation.
		exclusionTTL: 1 * time.Hour,
	}

	// Initialize neural network model
	mlModel, err := ml.NewQualityModel(filepath.Join(dataDir, "ml"))
	if err != nil {
		log.Warn().Err(err).Msg("failed to initialize ML model, using heuristics")
		s.mlEnabled = false
	} else {
		s.mlModel = mlModel
		s.mlEnabled = true
		log.Info().Msg("🧠 Neural network circuit selector initialized")
	}

	// Load historical data
	s.loadData()

	return s
}

// RecordCircuitPerformance records performance metrics for a circuit
func (s *SmartCircuitSelector) RecordCircuitPerformance(
	exitFingerprint, exitCountry, destination string,
	latencyMs, bandwidthKbps float64,
	success bool,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create exit performance record
	perf, exists := s.exitPerformance[exitFingerprint]
	if !exists {
		perf = &CircuitPerformance{
			ExitFingerprint:  exitFingerprint,
			ExitCountry:      exitCountry,
			DestinationStats: make(map[string]*DestinationPerf),
		}
		s.exitPerformance[exitFingerprint] = perf
	}

	// Update with exponential moving average
	alpha := s.learningRate
	perf.AvgLatency = alpha*latencyMs + (1-alpha)*perf.AvgLatency
	perf.AvgBandwidth = alpha*bandwidthKbps + (1-alpha)*perf.AvgBandwidth

	successVal := 0.0
	if success {
		successVal = 1.0
	}
	perf.SuccessRate = alpha*successVal + (1-alpha)*perf.SuccessRate
	perf.SampleCount++
	perf.LastUpdated = time.Now()

	// Update destination-specific stats
	if destination != "" {
		destPerf, exists := perf.DestinationStats[destination]
		if !exists {
			destPerf = &DestinationPerf{Domain: destination}
			perf.DestinationStats[destination] = destPerf
		}
		destPerf.AvgLatency = alpha*latencyMs + (1-alpha)*destPerf.AvgLatency
		destPerf.AvgBandwidth = alpha*bandwidthKbps + (1-alpha)*destPerf.AvgBandwidth
		destPerf.SampleCount++
	}

	// Feed to neural network for online learning
	if s.mlEnabled && s.mlModel != nil {
		features := ml.CircuitFeatures{
			LatencyNorm:   ml.NormalizeLatency(latencyMs),
			BandwidthNorm: ml.NormalizeBandwidth(bandwidthKbps),
			SuccessRate:   successVal,
			TimeOfDay:     ml.NormalizeTimeOfDay(time.Now()),
			SampleCount:   ml.NormalizeSamples(perf.SampleCount),
			Recency:       1.0, // Just observed = maximum recency
		}
		actualQuality := ml.ComputeActualQuality(latencyMs, bandwidthKbps, success)
		s.mlModel.RecordObservation(features, actualQuality)
	}

	// Persist periodically
	if perf.SampleCount%10 == 0 {
		go s.saveData()
	}
}

// PredictBestExits returns ranked list of best exits for a destination
func (s *SmartCircuitSelector) PredictBestExits(destination string, count int) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type exitScore struct {
		fingerprint string
		score       float64
	}

	var scores []exitScore

	for fp, perf := range s.exitPerformance {
		if perf.SampleCount < s.minSamples {
			continue
		}

		score := s.calculateScore(perf, destination)
		scores = append(scores, exitScore{fp, score})
	}

	// Sort by score (higher is better)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	// Return top N
	result := make([]string, 0, count)
	for i := 0; i < count && i < len(scores); i++ {
		result = append(result, scores[i].fingerprint)
	}

	return result
}

// calculateScore computes a performance score for an exit using neural network if available
func (s *SmartCircuitSelector) calculateScore(perf *CircuitPerformance, destination string) float64 {
	log := logger.WithComponent("ai")

	// Try neural network prediction first
	if s.mlEnabled && s.mlModel != nil {
		features := ml.CircuitFeatures{
			LatencyNorm:   ml.NormalizeLatency(perf.AvgLatency),
			BandwidthNorm: ml.NormalizeBandwidth(perf.AvgBandwidth),
			SuccessRate:   perf.SuccessRate,
			TimeOfDay:     ml.NormalizeTimeOfDay(time.Now()),
			SampleCount:   ml.NormalizeSamples(perf.SampleCount),
			Recency:       ml.NormalizeRecency(perf.LastUpdated),
		}

		score, err := s.mlModel.Predict(features)
		if err == nil {
			log.Debug().
				Str("exit", shortFingerprint(perf.ExitFingerprint)).
				Float64("ml_score", score).
				Msg("🧠 ML prediction used for circuit scoring")
			return score
		}
		log.Debug().Err(err).Msg("ML prediction failed, using heuristics")
		// Fall through to heuristics on error
	}

	// Fallback: heuristic-based scoring
	log.Debug().
		Str("exit", shortFingerprint(perf.ExitFingerprint)).
		Bool("ml_enabled", s.mlEnabled).
		Msg("📊 Using heuristic scoring (ML not available)")
	// Normalize metrics (lower latency = higher score, higher bandwidth = higher score)
	latencyScore := 1.0 / (1.0 + perf.AvgLatency/1000.0)    // Sigmoid-like normalization
	bandwidthScore := math.Log10(perf.AvgBandwidth+1) / 5.0 // Log scale, max ~5000 kbps
	successScore := perf.SuccessRate

	// Recency score (newer data is more valuable)
	hoursSinceUpdate := time.Since(perf.LastUpdated).Hours()
	recencyScore := math.Exp(-hoursSinceUpdate / 24.0) // Decay over 24 hours

	// Base score
	score := s.latencyWeight*latencyScore +
		s.bandwidthWeight*bandwidthScore +
		s.successWeight*successScore +
		s.recencyWeight*recencyScore

	// Boost if we have destination-specific data
	if destPerf, exists := perf.DestinationStats[destination]; exists {
		destLatencyScore := 1.0 / (1.0 + destPerf.AvgLatency/1000.0)
		destBandwidthScore := math.Log10(destPerf.AvgBandwidth+1) / 5.0

		// Blend destination-specific with general (50/50)
		score = 0.5*score + 0.25*destLatencyScore + 0.25*destBandwidthScore
	}

	return score
}

// GetPerformanceStats returns current performance statistics
func (s *SmartCircuitSelector) GetPerformanceStats() map[string]*CircuitPerformance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy
	result := make(map[string]*CircuitPerformance)
	for k, v := range s.exitPerformance {
		result[k] = v
	}
	return result
}

// TuneWeights adjusts the prediction weights based on actual performance
func (s *SmartCircuitSelector) TuneWeights(actualLatency, predictedLatency float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Simple gradient descent step
	error := actualLatency - predictedLatency

	// Gradient descent weight adjustment based on prediction error
	if error > 0 {
		// Prediction was too optimistic, increase latency weight
		s.latencyWeight += s.learningRate * 0.01
		s.bandwidthWeight -= s.learningRate * 0.005
	} else {
		// Prediction was pessimistic
		s.latencyWeight -= s.learningRate * 0.005
		s.bandwidthWeight += s.learningRate * 0.01
	}

	// Normalize weights to sum to 1
	total := s.latencyWeight + s.bandwidthWeight + s.successWeight + s.recencyWeight
	s.latencyWeight /= total
	s.bandwidthWeight /= total
	s.successWeight /= total
	s.recencyWeight /= total
}

// loadData loads historical performance data
func (s *SmartCircuitSelector) loadData() {
	dataPath := filepath.Join(s.dataDir, "circuit_performance.json")
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return // No data yet
	}

	var perfData map[string]*CircuitPerformance
	if err := json.Unmarshal(data, &perfData); err != nil {
		return
	}

	s.exitPerformance = perfData
}

// saveData persists performance data to disk
func (s *SmartCircuitSelector) saveData() {
	s.mu.RLock()
	data, err := json.MarshalIndent(s.exitPerformance, "", "  ")
	s.mu.RUnlock()

	if err != nil {
		return
	}

	dataPath := filepath.Join(s.dataDir, "circuit_performance.json")
	os.MkdirAll(s.dataDir, 0700)
	os.WriteFile(dataPath, data, 0600)
}

// DecayOldData reduces the weight of old performance data
func (s *SmartCircuitSelector) DecayOldData() {
	s.mu.Lock()
	defer s.mu.Unlock()

	threshold := time.Now().Add(-24 * time.Hour) // 24 hours for anonymity (was 7 days)

	for fp, perf := range s.exitPerformance {
		if perf.LastUpdated.Before(threshold) {
			// Reduce sample count to make new data more impactful
			perf.SampleCount = int(float64(perf.SampleCount) * s.decayFactor)

			// Remove if too old
			if perf.SampleCount < 1 {
				delete(s.exitPerformance, fp)
			}
		}
	}
}

// ExitRecommendation contains ML-based exit node recommendations
type ExitRecommendation struct {
	PreferredExits []string  // High-scoring exits (top 20%)
	AvoidExits     []string  // Low-scoring exits (bottom 20%) - temporary exclusion
	AvoidUntil     time.Time // When to re-evaluate avoided exits
	Confidence     float64   // Model confidence (based on sample count)
}

// GetExitRecommendations returns ML-based exit node recommendations
// These can be used to influence Tor's exit selection
func (s *SmartCircuitSelector) GetExitRecommendations() *ExitRecommendation {
	s.mu.RLock()
	defer s.mu.RUnlock()

	log := logger.WithComponent("ai")

	if !s.mlEnabled || s.mlModel == nil {
		return nil
	}

	type exitScore struct {
		fingerprint string
		score       float64
		sampleCount int
	}

	var scores []exitScore
	totalSamples := 0

	for fp, perf := range s.exitPerformance {
		if perf.SampleCount < s.minSamples {
			continue
		}

		score := s.calculateScore(perf, "")
		scores = append(scores, exitScore{fp, score, perf.SampleCount})
		totalSamples += perf.SampleCount
	}

	if len(scores) < 3 {
		// Not enough data to make recommendations
		return nil
	}

	// Sort by score (higher is better)
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].score > scores[j].score
	})

	// Calculate thresholds (top 20% = preferred, bottom 20% = avoid)
	// Limit to max 5 to preserve anonymity and prevent Tor issues
	topN := len(scores) / 5
	if topN < 1 {
		topN = 1
	}
	if topN > 5 {
		topN = 5
	}
	bottomN := len(scores) / 5
	if bottomN < 1 {
		bottomN = 1
	}
	if bottomN > 5 {
		bottomN = 5 // Max 5 exclusions to preserve anonymity
	}

	// Check if current exclusions have expired (TTL passed)
	exclusionsExpired := false
	if !s.exclusionStartTime.IsZero() && time.Since(s.exclusionStartTime) > s.exclusionTTL {
		exclusionsExpired = true
		log.Info().
			Dur("elapsed", time.Since(s.exclusionStartTime)).
			Msg("🔄 Exclusion TTL expired - re-evaluating exit nodes")
	}

	rec := &ExitRecommendation{
		PreferredExits: make([]string, 0, topN),
		AvoidExits:     make([]string, 0, bottomN),
		AvoidUntil:     s.exclusionStartTime.Add(s.exclusionTTL),
		Confidence:     float64(totalSamples) / 250.0, // Need 250 samples for full confidence
	}

	if rec.Confidence > 1.0 {
		rec.Confidence = 1.0
	}

	// Top performers
	for i := 0; i < topN && i < len(scores); i++ {
		rec.PreferredExits = append(rec.PreferredExits, scores[i].fingerprint)
	}

	// Poor performers (only if confidence is high enough - need 250+ samples)
	// Also reset if TTL expired to give exits another chance
	if rec.Confidence >= 1.0 && !exclusionsExpired {
		// Use cached exclusions if we have them and TTL hasn't expired
		if len(s.cachedAvoidExits) > 0 {
			rec.AvoidExits = s.cachedAvoidExits
		} else {
			// Calculate new exclusions
			for i := len(scores) - bottomN; i < len(scores); i++ {
				if i >= 0 {
					rec.AvoidExits = append(rec.AvoidExits, scores[i].fingerprint)
				}
			}
			// Cache exclusions and set start time (need write lock for this)
			// Note: This is done in a separate goroutine to avoid holding RLock
			if len(rec.AvoidExits) > 0 {
				go s.cacheExclusions(rec.AvoidExits)
			}
		}
	} else if exclusionsExpired {
		// Clear cached exclusions - they get a fresh chance
		go s.clearExclusions()
	}

	log.Info().
		Int("preferred", len(rec.PreferredExits)).
		Int("avoid", len(rec.AvoidExits)).
		Float64("confidence", rec.Confidence).
		Bool("ttl_expired", exclusionsExpired).
		Msg("🧠 ML exit recommendations generated")

	return rec
}

// cacheExclusions stores exclusions and sets the TTL start time
func (s *SmartCircuitSelector) cacheExclusions(exits []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log := logger.WithComponent("ai")

	s.cachedAvoidExits = exits
	s.exclusionStartTime = time.Now()

	log.Info().
		Int("count", len(exits)).
		Time("expires_at", s.exclusionStartTime.Add(s.exclusionTTL)).
		Msg("🔒 Cached exit exclusions with TTL")
}

// clearExclusions removes cached exclusions after TTL expires
func (s *SmartCircuitSelector) clearExclusions() {
	s.mu.Lock()
	defer s.mu.Unlock()

	log := logger.WithComponent("ai")

	prevCount := len(s.cachedAvoidExits)
	s.cachedAvoidExits = nil
	s.exclusionStartTime = time.Time{} // Reset to zero time

	log.Info().
		Int("cleared_count", prevCount).
		Msg("🔓 Cleared exit exclusions - exits get fresh chance")
}

// GetTorExitConfig returns Tor configuration lines for exit preferences
// Returns lines that can be added to torrc
func (s *SmartCircuitSelector) GetTorExitConfig() []string {
	rec := s.GetExitRecommendations()
	if rec == nil {
		return nil
	}

	var config []string

	// Only modify exit selection if confidence is high enough
	if rec.Confidence < 0.3 {
		return nil
	}

	// Prefer good exits (soft preference)
	if len(rec.PreferredExits) > 0 {
		// Note: This is informational - Tor doesn't have a "prefer" directive
		// We can use this info for logging/monitoring
	}

	// Temporarily avoid bad exits
	if len(rec.AvoidExits) > 0 && time.Now().Before(rec.AvoidUntil) {
		// ExcludeExitNodes takes fingerprints
		excludeList := ""
		for i, fp := range rec.AvoidExits {
			if i > 0 {
				excludeList += ","
			}
			excludeList += "$" + fp // $ prefix for fingerprint
		}
		config = append(config, "ExcludeExitNodes "+excludeList)
	}

	return config
}

// ShouldAvoidExit returns true if an exit should currently be avoided
func (s *SmartCircuitSelector) ShouldAvoidExit(fingerprint string) bool {
	rec := s.GetExitRecommendations()
	if rec == nil {
		return false
	}

	// Check if exclusion has expired
	if time.Now().After(rec.AvoidUntil) {
		return false // Give it another chance
	}

	for _, fp := range rec.AvoidExits {
		if fp == fingerprint {
			return true
		}
	}

	return false
}

// GetMLStats returns AI/ML statistics for display
func (s *SmartCircuitSelector) GetMLStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"ml_enabled":    s.mlEnabled,
		"exits_tracked": len(s.exitPerformance),
		"min_samples":   s.minSamples,
	}

	if s.mlEnabled && s.mlModel != nil {
		modelStats := s.mlModel.GetStats()
		for k, v := range modelStats {
			stats["ml_"+k] = v
		}
	}

	rec := s.GetExitRecommendations()
	if rec != nil {
		stats["preferred_exits"] = len(rec.PreferredExits)
		stats["avoid_exits"] = len(rec.AvoidExits)
		stats["confidence"] = rec.Confidence
	}

	return stats
}

// shortFingerprint returns the first 8 characters of a fingerprint for logging
func shortFingerprint(fp string) string {
	if len(fp) > 8 {
		return fp[:8]
	}
	return fp
}
