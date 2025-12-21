// Package ai provides AI-powered features for TorForge
package ai

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
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

// SmartCircuitSelector uses ML-like algorithms to select optimal circuits
type SmartCircuitSelector struct {
	mu sync.RWMutex

	// Historical performance data
	exitPerformance map[string]*CircuitPerformance

	// Prediction weights (learned over time)
	latencyWeight   float64
	bandwidthWeight float64
	successWeight   float64
	recencyWeight   float64

	// Configuration
	dataDir      string
	learningRate float64
	decayFactor  float64
	minSamples   int

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

// NewSmartCircuitSelector creates a new AI circuit selector
func NewSmartCircuitSelector(dataDir string) *SmartCircuitSelector {
	s := &SmartCircuitSelector{
		exitPerformance: make(map[string]*CircuitPerformance),
		currentCircuits: make(map[string]*LiveCircuitMetrics),
		dataDir:         dataDir,

		// Initial weights (will be tuned by learning)
		latencyWeight:   0.35,
		bandwidthWeight: 0.30,
		successWeight:   0.25,
		recencyWeight:   0.10,

		learningRate: 0.1,
		decayFactor:  0.95, // Old data becomes less important
		minSamples:   5,
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

// calculateScore computes a performance score for an exit
func (s *SmartCircuitSelector) calculateScore(perf *CircuitPerformance, destination string) float64 {
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

	threshold := time.Now().Add(-7 * 24 * time.Hour) // 7 days

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
